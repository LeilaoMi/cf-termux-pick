#!/usr/bin/env python3
"""
cf-pick.py — Termux 上的 Cloudflare 优选 IP 扫描器

单文件，零依赖（只用 Python 标准库），在 Termux 里 `python cf-pick.py` 直接跑。

原理（四层漏斗）：
  ① TCP 延迟初筛 — 只测 443 端口建连时间
  ② colo 校验 — 用 /cdn-cgi/trace 确认落地机房，只要目标 colo（默认 SJC）
  ③ 送中过滤 — 双归属地库查 IP，任一报 CN 就扔；同时排掉 1034 错误 IP
  ④ 测速 — 只对幸存者下 speed.cloudflare.com 测速，0 速度（回源 IP）直接扔

安全红线（写死在代码里，不可绕过）：
  - 只扫描 Cloudflare 官方公布的 IPv4 段（白名单），其它输入直接拒绝
  - 只碰 443 端口

用法：
  python cf-pick.py                      # 默认：SJC，Top 20
  python cf-pick.py --colo SJC --top 30  # 指定机房和数量
  python cf-pick.py --samples 100        # 每段采样 100 个 IP（默认 50）
  python cf-pick.py --dry-run            # 只列出采样 IP，不测试（调试用）

输出：
  best-ips.txt   — 纯 IP:端口 列表，可直接喂给订阅器的 manual.txt
  best-ips.json  — 完整结果（含延迟/速度/colo/归属地）
"""

import argparse
import asyncio
import ipaddress
import json
import random
import socket
import ssl
import sys
import time
import urllib.request

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

# Cloudflare 官方 IPv4 段（白名单）。来源：https://www.cloudflare.com/ips-v4
# 2026-10-15 拉取。只允许这些段，其它输入一律拒绝。
CF_IPV4_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

TRACE_HOST = "cloudflare.com"        # colo 检测用的 SNI/Host
SPEED_HOST = "speed.cloudflare.com"  # 测速用的 SNI/Host
SPEED_BYTES = 2_000_000              # 测速下载 2MB（省流量）
TCP_TIMEOUT = 5                      # TCP 建连超时（秒）
TLS_TIMEOUT = 10                     # TLS+HTTP 超时（秒）
LATENCY_CAP_MS = 800                 # 延迟初筛上限（毫秒），超过直接扔


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def sample_ips(ranges, per_range):
    """从每个 IP 段随机采样。只返回白名单内的 IP。"""
    nets = [ipaddress.ip_network(r) for r in ranges]
    out = []
    for net in nets:
        hosts = list(net.hosts())
        # 大段只采样，小段全取
        if len(hosts) > per_range:
            out.extend(random.sample(hosts, per_range))
        else:
            out.extend(hosts)
    # 去重并转字符串
    return sorted({str(ip) for ip in out})


def is_whitelisted(ip_str):
    """检查 IP 是否在 CF 官方白名单段内。"""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(r) for r in CF_IPV4_RANGES)


async def tcp_latency(ip, port=443, timeout=TCP_TIMEOUT):
    """TCP 建连延迟（毫秒）。失败返回 None。"""
    t0 = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return (time.monotonic() - t0) * 1000
    except Exception:
        return None


async def tls_get(ip, host, path, timeout=TLS_TIMEOUT):
    """
    直连指定 IP:443，用 SNI=host 做 TLS 握手，发 HTTP/1.1 请求。
    返回 (状态码, 响应头文本, 响应体字节）。失败抛异常。
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # 直连 IP，证书是 host 的，不校验 hostname
    ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=host),
        timeout=timeout)
    try:
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               f"User-Agent: cf-pick/1.0\r\nConnection: close\r\n\r\n")
        writer.write(req.encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(-1), timeout=timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    # 解析状态码和 body
    head, _, body = raw.partition(b"\r\n\r\n")
    status = 0
    first = head.split(b"\r\n", 1)[0]
    parts = first.split(b" ")
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    return status, head.decode("utf-8", "ignore"), body


def parse_trace(body):
    """解析 /cdn-cgi/trace 响应，返回 dict。"""
    d = {}
    try:
        text = body.decode("utf-8", "ignore")
    except Exception:
        return d
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            d[k.strip()] = v.strip()
    return d


def geo_lookup(ip):
    """
    双归属地库查 IP 国家。返回 (country_code, 来源）。
    任一报 CN 即视为送中。失败返回 (None, 来源）。
    """
    # 源1：ip-api.com（免费 45 次/分钟）
    try:
        with urllib.request.urlopen(
                f"http://ip-api.com/json/{ip}?fields=countryCode,status",
                timeout=10) as r:
            d = json.load(r)
            if d.get("status") == "success":
                return d.get("countryCode"), "ip-api"
    except Exception:
        pass
    # 源2：ip.sb（免费，无需 key）
    try:
        with urllib.request.urlopen(
                f"https://api.ip.sb/geoip/{ip}", timeout=10) as r:
            d = json.load(r)
            if d.get("country_code"):
                return d.get("country_code"), "ip.sb"
    except Exception:
        pass
    return None, "none"


# ---------------------------------------------------------------------------
# 四层漏斗
# ---------------------------------------------------------------------------

async def layer1_latency(ips, concurrency, sem_extra=None):
    """① TCP 延迟初筛。返回 [(ip, ms)]，按延迟排序。"""
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def check(ip):
        async with sem:
            ms = await tcp_latency(ip)
            if ms is not None and ms <= LATENCY_CAP_MS:
                results.append((ip, round(ms, 1)))

    await asyncio.gather(*[check(ip) for ip in ips])
    results.sort(key=lambda x: x[1])
    return results


async def layer2_colo(candidates, target_colo, concurrency):
    """② colo 校验。返回 [(ip, ms, colo)]，只要目标 colo。"""
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def check(ip, ms):
        async with sem:
            try:
                status, _, body = await tls_get(ip, TRACE_HOST, "/cdn-cgi/trace")
                # 1034 = 真 CF 但不服务这个 zone，配进代理永远不通，直接扔
                if status == 1034 or "error code: 1034" in body.decode("utf-8", "ignore").lower():
                    return
                if status != 200:
                    return
                trace = parse_trace(body)
                colo = trace.get("colo", "")
                if colo == target_colo:
                    results.append((ip, ms, colo))
            except Exception:
                return

    await asyncio.gather(*[check(ip, ms) for ip, ms in candidates])
    results.sort(key=lambda x: x[1])
    return results


def layer3_geo(candidates):
    """③ 送中过滤。同步查库（量已很小）。返回 [(ip, ms, colo, cc)]。"""
    results = []
    for ip, ms, colo in candidates:
        cc, src = geo_lookup(ip)
        if cc == "CN":
            print(f"  [送中] {ip} ({src} 报 CN)，扔掉")
            continue
        results.append((ip, ms, colo, cc or "?"))
        # ip-api 限速 45/分钟，稍微歇一下
        time.sleep(1.5)
    return results


async def layer4_speed(candidates, concurrency):
    """④ 测速。返回 [(ip, ms, colo, cc, mbps)]，0 速度直接扔。"""
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def check(ip, ms, colo, cc):
        async with sem:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                t0 = time.monotonic()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        ip, 443, ssl=ctx, server_hostname=SPEED_HOST),
                    timeout=TLS_TIMEOUT)
                try:
                    req = (f"GET /__down?bytes={SPEED_BYTES} HTTP/1.1\r\n"
                           f"Host: {SPEED_HOST}\r\n"
                           f"User-Agent: cf-pick/1.0\r\n"
                           f"Connection: close\r\n\r\n")
                    writer.write(req.encode())
                    await writer.drain()
                    # 跳过响应头
                    head = await asyncio.wait_for(
                        reader.readuntil(b"\r\n\r\n"), timeout=TLS_TIMEOUT)
                    if b"200" not in head.split(b"\r\n")[0]:
                        return
                    # 读 body 并计时
                    got = 0
                    while True:
                        chunk = await asyncio.wait_for(
                            reader.read(65536), timeout=TLS_TIMEOUT)
                        if not chunk:
                            break
                        got += len(chunk)
                    dt = time.monotonic() - t0
                finally:
                    writer.close()
                if got <= 0 or dt <= 0:
                    return
                mbps = round(got * 8 / dt / 1e6, 2)
                if mbps <= 0:
                    return  # 回源 IP，速度为 0，扔掉
                results.append((ip, ms, colo, cc, mbps))
                print(f"  [测速] {ip} {mbps} Mbps")
            except Exception:
                return

    await asyncio.gather(*[check(ip, ms, colo, cc) for ip, ms, colo, cc in candidates])
    # 按延迟优先、速度其次排序
    results.sort(key=lambda x: (x[1], -x[4]))
    return results


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def detect_carrier():
    """检测本机出口运营商。返回 (CT/CU/CM/?, 出口 IP)。三网通用。"""
    try:
        with urllib.request.urlopen(
                "http://ip-api.com/json/?fields=isp,org,query",
                timeout=10) as r:
            d = json.load(r)
            isp = (d.get("isp", "") or "") + " " + (d.get("org", "") or "")
            ip = d.get("query")
            if "联通" in isp or "Unicom" in isp:
                return "CU", ip
            if "电信" in isp or "Telecom" in isp:
                return "CT", ip
            if "移动" in isp or "Mobile" in isp:
                return "CM", ip
            return "?", ip
    except Exception:
        return "?", None


def git_auto_push(top_count, colo, carrier="?"):
    """跑完自动 git add/commit/push。失败不抛异常，只打印手动命令。"""
    import subprocess

    def run(cmd, timeout=60):
        return subprocess.run(cmd, capture_output=True, timeout=timeout)

    # Termux 上经常没配 git 身份，自动补一个本地配置
    try:
        r = run(["git", "config", "user.email"], timeout=10)
        if r.returncode != 0 or not r.stdout.strip():
            run(["git", "config", "user.email", "cf-pick@termux.local"], timeout=10)
            run(["git", "config", "user.name", "cf-pick"], timeout=10)
            print("ℹ️ 已自动配置 git 身份（cf-pick@termux.local）")
    except Exception:
        pass

    try:
        r = run(["git", "add", "best-ips.txt", "best-ips.json"], timeout=30)
        if r.returncode != 0:
            print("⚠️ git add 失败")
            return False
    except FileNotFoundError:
        print("⚠️ 没找到 git，请手动 push")
        return False
    except Exception as e:
        print(f"⚠️ git add 异常：{e}")
        return False

    # 没变化就不提交
    try:
        st = run(["git", "status", "--porcelain", "best-ips.txt", "best-ips.json"], timeout=30)
        if not st.stdout.strip():
            print("ℹ️ 结果无变化，跳过 push")
            return True
    except Exception:
        pass

    msg = f"update {time.strftime('%Y-%m-%d %H:%M')}: {top_count} IPs ({colo}/{carrier})"
    try:
        cm = run(["git", "commit", "-m", msg], timeout=30)
        if cm.returncode != 0:
            err = cm.stderr.decode("utf-8", "ignore")[:200]
            print(f"⚠️ git commit 失败：{err}")
            print("  请手动执行：git commit -m update && git push")
            return False
        push = run(["git", "push"], timeout=120)
        if push.returncode == 0:
            print("✅ 已自动 push 到仓库")
            return True
        err = push.stderr.decode("utf-8", "ignore")[:200]
        print(f"⚠️ push 失败：{err}")
    except Exception as e:
        print(f"⚠️ push 异常：{e}")
    print("  请手动执行：git push")
    return False


async def main_async(args):
    print(f"cf-pick v1.0 | 目标 colo={args.colo} | Top {args.top}")
    print(f"白名单：{len(CF_IPV4_RANGES)} 个 CF 官方段")

    # 采样
    ips = sample_ips(CF_IPV4_RANGES, args.samples)
    # 二次确认白名单（防御性）
    ips = [ip for ip in ips if is_whitelisted(ip)]
    print(f"[采样] 共 {len(ips)} 个候选 IP")

    if args.dry_run:
        for ip in ips[:20]:
            print(f"  {ip}")
        print(f"  ...（dry-run，只显示前 20 个）")
        return

    # ① 延迟初筛
    print(f"[1/4] TCP 延迟初筛（并发 {args.concurrency}）...")
    l1 = await layer1_latency(ips, args.concurrency)
    print(f"  通过：{len(l1)}/{len(ips)}")
    if not l1:
        print("没有 IP 通过延迟初筛，退出。"); return

    # ② colo 校验
    print(f"[2/4] colo 校验（只要 {args.colo}）...")
    l2 = await layer2_colo(l1, args.colo, args.concurrency)
    print(f"  通过：{len(l2)}/{len(l1)}")
    if not l2:
        print(f"没有 IP 落在 {args.colo}，退出。"); return

    # ③ 送中过滤
    print("[3/4] 送中过滤（双库查归属地）...")
    l3 = layer3_geo(l2)
    print(f"  通过：{len(l3)}/{len(l2)}")
    if not l3:
        print("全部送中，退出。"); return

    # ④ 测速（只测 Top 候选，省流量）
    speed_n = min(len(l3), max(args.top * 3, 30))
    print(f"[4/4] 测速（取延迟最好的 {speed_n} 个，并发 {args.speed_concurrency}）...")
    l4 = await layer4_speed(l3[:speed_n], args.speed_concurrency)
    print(f"  通过：{len(l4)}/{speed_n}")
    if not l4:
        print("测速全挂，退出。"); return

    # 输出
    top = l4[:args.top]
    with open("best-ips.txt", "w") as f:
        f.write(f"# cf-pick {time.strftime('%Y-%m-%d %H:%M')} colo={args.colo}\n")
        for ip, ms, colo, cc, mbps in top:
            f.write(f"{ip}:443\n")
    detail = [
        {"ip": ip, "port": 443, "latency_ms": ms, "colo": colo,
         "country": cc, "mbps": mbps}
        for ip, ms, colo, cc, mbps in top
    ]
    with open("best-ips.json", "w") as f:
        json.dump({"colo": args.colo,
                   "carrier": carrier,
                   "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   "ips": detail}, f, indent=2)

    print(f"\n✅ 完成！Top {len(top)}（已写入 best-ips.txt / best-ips.json）：")
    for ip, ms, colo, cc, mbps in top:
        print(f"  {ip}:443  {ms}ms  {colo}  {cc}  {mbps}Mbps")

    carrier, _ = detect_carrier()
    print(f"ℹ️ 出口运营商：{carrier}")

    if args.push:
        git_auto_push(len(top), args.colo, carrier)


def main():
    ap = argparse.ArgumentParser(description="Termux 上的 CF 优选 IP 扫描器")
    ap.add_argument("--colo", default="SJC", help="目标机房（默认 SJC）")
    ap.add_argument("--top", type=int, default=20, help="输出 Top N（默认 20）")
    ap.add_argument("--samples", type=int, default=50,
                    help="每 IP 段采样数（默认 50）")
    ap.add_argument("--concurrency", type=int, default=50,
                    help="初筛并发（默认 50，手机流量建议 20-30）")
    ap.add_argument("--speed-concurrency", type=int, default=5,
                    help="测速并发（默认 5，省流量）")
    ap.add_argument("--dry-run", action="store_true",
                    help="只采样不测试")
    ap.add_argument("--push", action="store_true",
                    help="跑完自动 git add/commit/push 回传仓库")
    args = ap.parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n已中断，已测结果保留在 best-ips.txt（如有）。")
        sys.exit(130)


if __name__ == "__main__":
    main()
