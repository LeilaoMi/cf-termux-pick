#!/usr/bin/env python3
"""
cf-pick.py v3.7 — Cloudflare 优选 IP（双栈 + 稳定性 + GFW 感知）

Phase 1: 双栈采样 → 四层漏斗（TCP延迟 → colo → 送中过滤 → 测速）
Phase 2: 稳定性 burn-in（多轮复测，识别 GFW 残余审查模式）
Phase 3: GFW 感知分类（rst_midstream → 冷却 5 分钟，不是扔掉）
Phase 4: SQLite 历史库（时间衰减可靠性评分）

用法：
  python cf-pick.py                      # v1 行为：只跑漏斗
  python cf-pick.py --stability 5        # + 5 轮稳定性测试
  python cf-pick.py --stability 5 --v6-only   # 只测 IPv6
  python cf-pick.py --probe-trigger 1.2.3.4  # 触发器探测
  python cf-pick.py --push               # 跑完自动推送到仓库

零第三方依赖：只用 Python 标准库。
"""

import argparse
import hashlib
import ipaddress
import json
import random
import socket
import sqlite3
import ssl
import statistics
import subprocess
import os
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------- 配置

# Cloudflare 官方 IPv4 段（2026-10-15 从 cloudflare.com/ips-v4 拉取）
CF_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

# Cloudflare 官方 IPv6 段（2026-10-15 从 cloudflare.com/ips-v6 拉取）
CF_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
    "2c0f:f248::/32",
]

# 实际有 HTTPS 应答的 Cloudflare IPv6 /48（来自 XIU2/CloudflareSpeedTest ipv6.txt，2026-10-16）。
# 官方 /32、/29 里绝大部分地址没人监听，在整段里随机抽基本全是空号，所以 v6 只在这些 /48 里抽。
CF_V6_HOT = [
    "2400:cb00:2049::/48", "2400:cb00:f00e::/48", "2606:4700:10::/48", "2606:4700:130::/48",
    "2606:4700:3000::/48", "2606:4700:3001::/48", "2606:4700:3002::/48", "2606:4700:3003::/48",
    "2606:4700:3004::/48", "2606:4700:3005::/48", "2606:4700:3006::/48", "2606:4700:3007::/48",
    "2606:4700:3008::/48", "2606:4700:3009::/48", "2606:4700:3010::/48", "2606:4700:3011::/48",
    "2606:4700:3012::/48", "2606:4700:3013::/48", "2606:4700:3014::/48", "2606:4700:3015::/48",
    "2606:4700:3016::/48", "2606:4700:3017::/48", "2606:4700:3018::/48", "2606:4700:3019::/48",
    "2606:4700:3020::/48", "2606:4700:3021::/48", "2606:4700:3022::/48", "2606:4700:3023::/48",
    "2606:4700:3024::/48", "2606:4700:3025::/48", "2606:4700:3026::/48", "2606:4700:3027::/48",
    "2606:4700:3028::/48", "2606:4700:3029::/48", "2606:4700:3030::/48", "2606:4700:3031::/48",
    "2606:4700:3032::/48", "2606:4700:3033::/48", "2606:4700:3034::/48", "2606:4700:3035::/48",
    "2606:4700:3036::/48", "2606:4700:3037::/48", "2606:4700:3038::/48", "2606:4700:3039::/48",
    "2606:4700:a0::/48", "2606:4700:a1::/48", "2606:4700:a8::/48", "2606:4700:a9::/48",
    "2606:4700:a::/48", "2606:4700:b::/48", "2606:4700:c::/48", "2606:4700:d0::/48",
    "2606:4700:d1::/48", "2606:4700:d::/48", "2606:4700:e0::/48", "2606:4700:e1::/48",
    "2606:4700:e2::/48", "2606:4700:e3::/48", "2606:4700:e4::/48", "2606:4700:e5::/48",
    "2606:4700:e6::/48", "2606:4700:e7::/48", "2606:4700:e::/48", "2606:4700:f1::/48",
    "2606:4700:f2::/48", "2606:4700:f3::/48", "2606:4700:f4::/48", "2606:4700:f5::/48",
    "2606:4700:f::/48", "2803:f800:50::/48", "2803:f800:51::/48", "2a06:98c1:3100::/48",
    "2a06:98c1:3101::/48", "2a06:98c1:3102::/48", "2a06:98c1:3103::/48", "2a06:98c1:3104::/48",
    "2a06:98c1:3105::/48", "2a06:98c1:3106::/48", "2a06:98c1:3107::/48", "2a06:98c1:3108::/48",
    "2a06:98c1:3109::/48", "2a06:98c1:310a::/48", "2a06:98c1:310b::/48", "2a06:98c1:310c::/48",
    "2a06:98c1:310d::/48", "2a06:98c1:310e::/48", "2a06:98c1:310f::/48", "2a06:98c1:3120::/48",
    "2a06:98c1:3121::/48", "2a06:98c1:3122::/48", "2a06:98c1:3123::/48", "2a06:98c1:3200::/48",
    "2a06:98c1:50::/48", "2a06:98c1:51::/48", "2a06:98c1:54::/48", "2a06:98c1:58::/48",
]

# GFW 残余审查时长：学术实测 120-180 秒，冷却取 300 秒保底
GFW_COOLDOWN = 300

# 并发配置（手机安全值）
CONC_L1 = 20  # TCP 握手：最便宜
CONC_L2 = 10  # TLS trace：耗 CPU
CONC_L3 = 5   # Geo API：ip-api 限流 45/分钟
CONC_L4 = 2   # 测速：最耗流量

# 测速参数（单位都是 MB/s）
SPEED_BYTES = 10_000_000      # >10MB 不带 Referer 会被 403，批量还易 429
SPEED_MIN_MBS = 0.3           # 绝对下限
SPEED_CANDIDATES = 30         # L4 测速候选数（按丢包/延迟排序后取）
MIN_OUTPUT = 10               # 输出不足时用上次仍可达的 IP 补齐
SPEED_STATUS = {}             # ip -> HTTP 状态码（诊断用）

# 测速目标
SPEED_URL_PATH = "/__down"
SPEED_SNI = "speed.cloudflare.com"

# AI 目标感知测试（只做 TLS 握手，不调 API、不耗 key）
# 只测 CF 托管的 AI 域名（深挖结论：anthropic/google 不在 CF 上，测了必挂）
AI_TARGETS = [
    "api.openai.com",     # CF
    "api.groq.com",       # CF
    "api.mistral.ai",     # CF
    "openrouter.ai",      # CF
]

DB_PATH = "ip_history.db"


# ---------------------------------------------------------------- 基础工具

def get_good_neighborhoods(conn, family=4, min_score=60, days=7, limit=20):
    """从历史库提取优质 /24 网段（智能采样）。

    返回 [(network_str, weight)]，按加权成功率排序。
    zqy857 邻域加权思想：出过好 IP 的 C 段优先。
    """
    import time as _t
    cutoff = _t.time() - days * 86400
    rows = conn.execute(
        """SELECT ip, mbps, ok FROM history
           WHERE family=? AND ts>? AND mbps > 0""",
        (family, cutoff)).fetchall()
    if not rows:
        return []
    # 按 /24 聚合
    from collections import defaultdict
    nets = defaultdict(lambda: {"ok": 0, "total": 0, "mbps_sum": 0.0})
    for ip, mbps, ok in rows:
        try:
            net = str(ipaddress.ip_network(ip + "/24", strict=False))
            nets[net]["total"] += 1
            nets[net]["mbps_sum"] += mbps or 0
            if ok:
                nets[net]["ok"] += 1
        except Exception:
            continue
    scored = []
    for net, d in nets.items():
        if d["total"] < 2:
            continue  # 样本太少不信
        rate = d["ok"] / d["total"]
        avg_mbps = d["mbps_sum"] / d["total"]
        # 权重 = 成功率 × 速度因子
        w = rate * min(avg_mbps / 10.0, 1.0)
        if w > 0.3:  # 阈值
            scored.append((net, w))
    scored.sort(key=lambda x: -x[1])
    return scored[:limit]


def sample_ips(family, count, conn=None, exploit_ratio=0.6):
    """整数范围随机采样（60% 优质邻域 + 40% 随机探索）。

    conn=None 时退化为纯随机（冷启动）。
    """
    ranges = CF_V4 if family == 4 else CF_V6
    out = set()

    if family == 6:
        # 每个 /48 等概率，块内随机取 host（不按地址数加权，否则全落进最大那段）
        nets6 = [ipaddress.ip_network(c) for c in CF_V6_HOT]
        guard = 0
        while len(out) < count and guard < count * 10:
            guard += 1
            net = random.choice(nets6)
            base = int(net.network_address)
            # 低 64 位里随机；高位前 16 位子网也随机
            ip_int = base + (random.getrandbits(16) << 64) + random.getrandbits(64)
            out.add(str(ipaddress.ip_address(ip_int)))
        return list(out)

    # 智能部分：从优质 /24 里采样
    smart_count = 0
    if conn is not None and family == 4:  # v6 暂不做邻域（地址空间太大）
        neighborhoods = get_good_neighborhoods(conn, family)
        if neighborhoods:
            smart_target = int(count * exploit_ratio)
            nets = [ipaddress.ip_network(n) for n, _ in neighborhoods]
            weights = [w for _, w in neighborhoods]
            total_w = sum(weights)
            while len(out) < smart_target:
                r = random.uniform(0, total_w)
                for net, w in zip(nets, weights):
                    r -= w
                    if r <= 0:
                        # /24 内随机取一个 host
                        base = int(net.network_address)
                        ip_int = base + random.randint(1, 254)
                        out.add(str(ipaddress.ip_address(ip_int)))
                        break
            smart_count = len(out)
            print(f"  智能采样：{smart_count} 个（来自 {len(neighborhoods)} 个优质 /24）")

    # 随机部分：补足剩余。IPv4 先在所有 /24 里不放回地均匀抽，再在 /24 内随机取一个 host
    # （思路同 XIU2 的每 /24 取 1 个），避免 104.16/13、172.64/13 两个大段占满样本、同一 /24 重复抽。
    nets = [ipaddress.ip_network(cidr) for cidr in ranges]
    need = count - len(out)
    if family == 4 and need > 0:
        blocks = []  # (network_int, 该网段里 /24 的个数)
        for net in nets:
            n24 = max(1, net.num_addresses // 256)
            blocks.append((int(net.network_address), n24))
        total24 = sum(n for _, n in blocks)
        picked = random.sample(range(total24), min(need * 2, total24))
        for idx in picked:
            if len(out) >= count:
                break
            for base, n24 in blocks:
                if idx < n24:
                    ip_int = base + idx * 256 + random.randint(1, 254)
                    out.add(str(ipaddress.ip_address(ip_int)))
                    break
                idx -= n24
    weights = [n.num_addresses for n in nets]
    total = sum(weights)
    guard = 0
    while len(out) < count and guard < count * 10:
        guard += 1
        r = random.uniform(0, total)
        for net, w in zip(nets, weights):
            r -= w
            if r <= 0:
                lo = int(net.network_address) + 1
                hi = int(net.broadcast_address) - 1
                if family == 6:
                    hi = int(net.network_address) + net.num_addresses - 1
                ip_int = random.randint(lo, hi)
                out.add(str(ipaddress.ip_address(ip_int)))
                break
    if smart_count:
        print(f"  随机探索：{len(out) - smart_count} 个")
    return list(out)


def tcp_ping(ip, port=443, timeout=3):
    """TCP 握手延迟（秒）。失败返回 None。"""
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        t0 = time.monotonic()
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        dt = time.monotonic() - t0
        s.close()
        return dt
    except Exception:
        return None


def tls_handshake(ip, sni, port=443, timeout=8):
    """
    TLS 握手测试。
    返回 (ok, fail_type, detail)：
      ok=True → (True, "ok", tls_version)
      握手阶段失败 → (False, "tls_fail", err)
      建连失败 → (False, "timeout", err)
    """
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return False, "timeout", str(e)[:80]

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t0 = time.monotonic()
        ss = ctx.wrap_socket(s, server_hostname=sni)
        dt = time.monotonic() - t0
        ver = ss.version()
        ss.close()
        return True, "ok", f"{ver}/{dt:.2f}s"
    except (ssl.SSLError, ssl.CertificateError, OSError) as e:
        try:
            s.close()
        except Exception:
            pass
        return False, "tls_fail", str(e)[:80]


def fetch_trace(ip, sni="speed.cloudflare.com", timeout=10):
    """抓 /cdn-cgi/trace，返回 dict。失败返回 None。"""
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=sni)
        req = (f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {sni}\r\n"
               f"Connection: close\r\nUser-Agent: cf-pick/3.7\r\n\r\n")
        ss.sendall(req.encode())
        data = b""
        while True:
            chunk = ss.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 16384:
                break
        ss.close()
        text = data.decode("utf-8", "ignore")
        # 1034 = 边缘回源，不服务这个 zone
        if "1034" in text[:200] or "error code: 1034" in text.lower():
            return {"_error": "1034"}
        # Zeus: 403/409/429 = 可达但拒绝，直接丢弃不重试
        first_line = text.split("\r\n", 1)[0] if "\r\n" in text else ""
        if any(code in first_line for code in ("403", "409", "429")):
            return {"_blocked": True}
        body = text.split("\r\n\r\n", 1)[-1]
        d = {}
        for line in body.strip().split("\n"):
            if "=" in line:
                k, v = line.split("=", 1)
                d[k.strip()] = v.strip()
        return d if d.get("colo") else None
    except Exception:
        return None


def check_geo(ip, timeout=10):
    """归属地 + 代理标记检查（ipapi.is 已死，用 ip-api proxy 字段替代）。

    返回 (is_cn, country, is_proxy)。失败返回 (False, '?', False)。
    保留单查接口，批量走 check_geo_batch。
    """
    r = check_geo_batch([ip], timeout=timeout)
    if r and ip in r:
        return r[ip]
    return False, "?", False


def _geo_single(ip, timeout=8):
    """单个 IP 的三级降级（GET 优先，batch POST 已被墙）。"""
    # L1: ip-api.com GET（最快）
    try:
        url = (f"http://ip-api.com/json/{ip}"
               f"?fields=status,country,countryCode,proxy")
        with urllib.request.urlopen(url, timeout=timeout) as r:
            d = json.load(r)
        if d.get("status") == "success":
            cc = d.get("countryCode", "?")
            return (cc == "CN"), d.get("country", "?"), bool(d.get("proxy", False))
    except Exception:
        pass
    # L2: ipwho.is
    try:
        with urllib.request.urlopen(f"http://ipwho.is/{ip}", timeout=timeout) as r:
            d = json.load(r)
        if d.get("success"):
            cc = d.get("country_code", "?")
            return (cc == "CN"), d.get("country", "?"), False
    except Exception:
        pass
    # L3: db-ip.com
    try:
        with urllib.request.urlopen(f"https://api.db-ip.com/v2/free/{ip}",
                                    timeout=timeout) as r:
            d = json.load(r)
        cc = d.get("countryCode", "?")
        return (cc == "CN"), d.get("countryName", "?"), False
    except Exception:
        pass
    return (False, "?", False)


def check_geo_batch(ips, timeout=15):
    """并发 Geo 查询（5 并发，GET 优先）。
    之前的 batch POST 已被墙，改回 GET + 并发。

    返回 {ip: (is_cn, country, is_proxy)}。
    """
    if not ips:
        return {}
    out = {}
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(_geo_single, ip): ip for ip in ips}
        for fu in as_completed(futs):
            ip = futs[fu]
            try:
                out[ip] = fu.result()
            except Exception:
                out[ip] = (False, "?", False)
    failed = sum(1 for v in out.values() if v[1] == "?")
    if failed:
        print(f"  ⚠️ {failed} 个 IP Geo 全失败，不阻塞")
    return out
def speed_test(ip, sni=SPEED_SNI, seconds=8, timeout=15,
               early_exit_mbs=2.0):
    """测下载速度（MB/s）。1s 热身 + <2MB/s 早退。失败返回 0。"""
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=sni)
        req = (f"GET {SPEED_URL_PATH}?bytes={SPEED_BYTES} HTTP/1.1\r\n"
               f"Host: {sni}\r\nConnection: close\r\n"
               f"Referer: https://{sni}/\r\n"
               f"User-Agent: cf-pick/3.7\r\n\r\n")
        ss.sendall(req.encode())
        # 跳过响应头
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = ss.recv(4096)
            if not chunk:
                break
            head += chunk
        # 解析状态码，非 200 直接判 0 并记录原因
        try:
            status = int(head.split(b"\r\n", 1)[0].split()[1])
        except Exception:
            status = 0
        SPEED_STATUS[ip] = status
        if status != 200:
            ss.close()
            return 0.0
        body_start = head.split(b"\r\n\r\n", 1)
        received = len(body_start[1]) if len(body_start) > 1 else 0
        t0 = time.monotonic()
        warmed = False
        w0, w_recv = t0, received
        while time.monotonic() - t0 < seconds:
            chunk = ss.recv(65536)
            if not chunk:
                break
            received += len(chunk)
            el = time.monotonic() - t0
            # 早退：1s 热身后，若 2s 窗口速度 <2MB/s，直接中断
            if not warmed and el >= 1.0:
                warmed = True
                w0, w_recv = time.monotonic(), received
            elif warmed and time.monotonic() - w0 >= 2.0:
                w_dt = time.monotonic() - w0
                w_mbps = ((received - w_recv) / 1024 / 1024) / w_dt if w_dt > 0 else 0
                if w_mbps < early_exit_mbs:
                    break
                w0, w_recv = time.monotonic(), received
        dt = time.monotonic() - t0
        ss.close()
        if dt <= 0:
            return 0.0
        return (received / 1024 / 1024) / dt
    except Exception:
        return 0.0


# ---------------------------------------------------------------- Phase 2: 稳定性

def stability_round(ip, sni=SPEED_SNI):
    """
    单轮稳定性测试：TCP → TLS → 小下载。
    返回 dict(ip, ok, fail_type, latency_ms, mbps, ts)。
    fail_type: ok | timeout | tls_fail | rst_midstream | speed_zero
    """
    t0 = time.monotonic()
    lat = tcp_ping(ip, timeout=3)
    if lat is None:
        return {"ip": ip, "ok": False, "fail_type": "timeout",
                "latency_ms": None, "mbps": 0.0, "ts": time.time()}

    ok, ftype, detail = tls_handshake(ip, sni, timeout=8)
    if not ok:
        return {"ip": ip, "ok": False, "fail_type": ftype,
                "latency_ms": round(lat * 1000, 1), "mbps": 0.0, "ts": time.time()}

    # TLS 成功，尝试小下载来探测传输中 RST
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=sni)
        req = (f"GET {SPEED_URL_PATH}?bytes=3000000 HTTP/1.1\r\n"
               f"Host: {sni}\r\nConnection: close\r\n"
               f"User-Agent: cf-pick/3.7\r\n\r\n")
        ss.sendall(req.encode())
        received = 0
        t1 = time.monotonic()
        try:
            while time.monotonic() - t1 < 10:
                chunk = ss.recv(65536)
                if not chunk:
                    break
                received += len(chunk)
                if received >= 3000000:
                    break
        except (ConnectionResetError, ssl.SSLError, OSError) as e:
            # 传输中被掐 → 疑似 GFW RST
            try:
                ss.close()
            except Exception:
                pass
            return {"ip": ip, "ok": False, "fail_type": "rst_midstream",
                    "latency_ms": round(lat * 1000, 1), "mbps": 0.0,
                    "ts": time.time(),
                    "note": f"传输中被掐({received}B): {str(e)[:60]}"}
        ss.close()
        dt = time.monotonic() - t1
        mbps = (received / 1024 / 1024) / dt if dt > 0 else 0
        if received == 0:
            return {"ip": ip, "ok": False, "fail_type": "speed_zero",
                    "latency_ms": round(lat * 1000, 1), "mbps": 0.0,
                    "ts": time.time()}
        return {"ip": ip, "ok": True, "fail_type": "ok",
                "latency_ms": round(lat * 1000, 1),
                "mbps": round(mbps, 2), "ts": time.time()}
    except Exception as e:
        return {"ip": ip, "ok": False, "fail_type": "timeout",
                "latency_ms": round(lat * 1000, 1), "mbps": 0.0,
                "ts": time.time(), "note": str(e)[:60]}


def burn_in(candidates, rounds=5, interval=60, sni=SPEED_SNI):
    """
    对候选 IP 做多轮 burn-in。
    返回 {ip: [round_results]}。
    GFW 感知：rst_midstream 的 IP 进入冷却，不立即重测。
    """
    results = {c["ip"]: [] for c in candidates}
    cooldown_until = {}  # ip -> timestamp

    for r in range(rounds):
        print(f"\n  —— 第 {r+1}/{rounds} 轮 ——")
        for c in candidates:
            ip = c["ip"]
            # 冷却中的跳过
            if cooldown_until.get(ip, 0) > time.time():
                print(f"  {ip} 冷却中，跳过")
                results[ip].append({"ip": ip, "ok": None, "fail_type": "cooldown",
                                    "latency_ms": None, "mbps": 0.0,
                                    "ts": time.time()})
                continue
            res = stability_round(ip, sni)
            results[ip].append(res)
            mark = "✅" if res["ok"] else f"❌({res['fail_type']})"
            lat = f"{res['latency_ms']}ms" if res["latency_ms"] else "-"
            print(f"  {ip} {mark} {lat} {res['mbps']}MB/s")
            # rst_midstream → 冷却 5 分钟（覆盖 120-180s 残余审查）
            if res["fail_type"] == "rst_midstream":
                cooldown_until[ip] = time.time() + GFW_COOLDOWN
                print(f"    → 疑似 GFW 掐断，冷却 {GFW_COOLDOWN//60} 分钟")
        if r < rounds - 1:
            print(f"  休眠 {interval}s...")
            time.sleep(interval)
    return results


def stability_score(rounds_results):
    """
    稳定性评分 0-100。
    成功率 × (1 - 变异系数惩罚)。
    cooldown 轮不计入（那是 GFW 封锁期，不是 IP 本身问题）。
    """
    valid = [r for r in rounds_results if r["fail_type"] != "cooldown"]
    if not valid:
        return 0.0, 0.0, 0.0
    ok_count = sum(1 for r in valid if r["ok"])
    success_rate = ok_count / len(valid)
    speeds = [r["mbps"] for r in valid if r["ok"] and r["mbps"] > 0]
    if len(speeds) >= 2:
        cv = statistics.stdev(speeds) / statistics.mean(speeds)
    else:
        cv = 0.0
    # 变异系数惩罚：CV 50% 时扣一半
    penalty = min(cv * 1.0, 0.9)
    score = success_rate * 100 * (1 - penalty)
    return round(score, 1), round(success_rate * 100, 1), round(cv * 100, 1)


# ---------------------------------------------------------------- Phase 4: 历史库

def detect_network_type():
    """检测网络类型（wifi/cellular/unknown）。

    termux-wifi-connectioninfo 没连 WiFi 时也会返回带 "ssid" 字段的 JSON（值是 <unknown ssid>），
    以前只查有没有 "ssid" 这个词，用 5G 也会被判成 wifi。现在看连接状态。
    """
    import subprocess
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                           capture_output=True, text=True, timeout=3)
        out = r.stdout.lower()
        if "wlan" in out:
            return "wifi"
        if "rmnet" in out or "ccmni" in out or "pdp" in out:
            return "cellular"
    except Exception:
        pass
    try:
        r = subprocess.run(["termux-wifi-connectioninfo"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            info = json.loads(r.stdout)
            connected = (str(info.get("supplicant_state", "")).upper() == "COMPLETED"
                         and info.get("ip") not in (None, "", "0.0.0.0")
                         and "unknown ssid" not in str(info.get("ssid", "")).lower())
            # 能上网（已经测出了出口）又没连 WiFi，就是蜂窝
            return "wifi" if connected else "cellular"
    except Exception:
        pass
    return "unknown"


def init_db(path=DB_PATH):
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE IF NOT EXISTS history (
        ip TEXT, ts REAL, family INTEGER, colo TEXT, carrier TEXT,
        latency_ms REAL, mbps REAL, ok INTEGER, fail_type TEXT,
        stability REAL
    )""")
    # 迁移：加新列（老数据不受影响）
    cols = [r[1] for r in conn.execute("PRAGMA table_info(history)")]
    migrations = [
        ("hour", "INTEGER"),
        ("network_type", "TEXT"),
        ("loss_pct", "REAL"),
        ("jitter_ms", "REAL"),
        ("ai_ok", "INTEGER"),
        ("is_proxy", "INTEGER"),
    ]
    for col, typ in migrations:
        if col not in cols:
            conn.execute(f"ALTER TABLE history ADD COLUMN {col} {typ}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON history(ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON history(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hour ON history(hour)")
    conn.commit()
    return conn


def record_history(conn, ip, family, colo, carrier, latency_ms, mbps,
                   ok, fail_type, stability, loss_pct=None, jitter_ms=None,
                   ai_ok=None, is_proxy=None):
    """记录时段、网络类型、分项指标。"""
    import datetime
    hour = datetime.datetime.now().hour
    net = detect_network_type()
    conn.execute(
        """INSERT INTO history
           (ip, ts, family, colo, carrier, latency_ms, mbps, ok, fail_type,
            stability, hour, network_type, loss_pct, jitter_ms, ai_ok, is_proxy)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (ip, time.time(), family, colo, carrier, latency_ms, mbps,
         1 if ok else 0, fail_type, stability, hour, net,
         loss_pct, jitter_ms, ai_ok, 1 if is_proxy else 0))
    conn.commit()


def historical_reliability(conn, ip, days=7):
    """
    时间衰减的历史可靠性 0-100。
    越近的记录权重越高（半衰期 3 天）。
    """
    cutoff = time.time() - days * 86400
    rows = conn.execute(
        "SELECT ts, ok FROM history WHERE ip=? AND ts>?",
        (ip, cutoff)).fetchall()
    if not rows:
        return None
    now = time.time()
    w_sum, ws = 0.0, 0.0
    for ts, ok in rows:
        age_days = (now - ts) / 86400
        w = 0.5 ** (age_days / 3.0)  # 3 天半衰期
        w_sum += w
        ws += w * ok
    return round(ws / w_sum * 100, 1) if w_sum > 0 else None


# ---------------------------------------------------------------- 目标感知 + 触发器探测

def ai_target_test(ip, timeout=8):
    """纯净度第二层：AI 目标 TLS 握手（不调 API）。返回 {domain: ok}。"""
    out = {}
    for dom in AI_TARGETS:
        ok, ftype, _ = tls_handshake(ip, dom, timeout=timeout)
        out[dom] = ok
    return out


def abuse_check(ip, timeout=10):
    """[已废弃] ipapi.is 滥用字段 2026-09 起需 API key，免费版已死。
    改用 check_geo 返回的 proxy 字段。保留签名防旧代码引用报错。

    返回 (is_clean, detail)：
      is_clean=True → 无滥用标记
      is_clean=False → 有 proxy/vpn/tor/abuser 标记
      is_clean=None → 检查失败（不阻塞）
    """
    try:
        url = f"https://api.ipapi.is/?q={ip}"
        with urllib.request.urlopen(url, timeout=timeout) as r:
            d = json.load(r)
        # cfnb 公式简化版
        flags = 0
        for key in ("is_proxy", "is_vpn", "is_tor", "is_crawler"):
            if d.get(key):
                flags += 1
        # abuser_score
        try:
            company_score = float(str(d.get("company", {}).get("abuser_score", "0")).split()[0] or 0)
            asn_score = float(str(d.get("asn", {}).get("abuse_score", "0")).split()[0] or 0)
            abuse = (company_score + asn_score) / 2
        except Exception:
            abuse = 0
        if d.get("is_bogon"):
            return False, "bogon"
        if flags > 0 or abuse > 0.2:
            return False, f"flags={flags} abuse={abuse:.2f}"
        return True, "clean"
    except Exception as e:
        return None, f"check_failed: {str(e)[:40]}"


def probe_trigger(ip, sni=SPEED_SNI):
    """
    触发器探测：分辨是 SNI 敏感还是流量敏感。
    L1: 只握手，不传数据
    L2: 握手 + 1KB
    L3: 握手 + 持续 60s 小流量
    """
    print(f"\n🔬 触发器探测：{ip}")
    # L1: 纯握手
    ok1, f1, d1 = tls_handshake(ip, sni, timeout=8)
    print(f"  L1 纯握手：{'✅' if ok1 else f'❌({f1})'} {d1}")
    if not ok1:
        print("  → 结论：SNI 或建连层被拦（握手都过不去）")
        return {"level": "L1", "verdict": "sni_or_connect_blocked"}

    # L2: 握手 + 1KB
    res2 = stability_round(ip, sni)
    # 手动截断：只看前 1KB 是否成功（stability_round 传 3MB，这里复用逻辑简化）
    print(f"  L2 小数据：{'✅' if res2['ok'] else f'❌({res2['fail_type']})'}")
    if not res2["ok"] and res2["fail_type"] == "rst_midstream":
        print("  → 结论：小数据就被掐，SNI 高度敏感")
        return {"level": "L2", "verdict": "sni_sensitive"}

    # L3: 持续 60s
    print("  L3 持续 60s 传输探测中...")
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(15)
        s.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=sni)
        req = (f"GET {SPEED_URL_PATH}?bytes=50000000 HTTP/1.1\r\n"
               f"Host: {sni}\r\nConnection: close\r\n"
               f"User-Agent: cf-pick/3.7\r\n\r\n")
        ss.sendall(req.encode())
        t0 = time.monotonic()
        received = 0
        killed_at = None
        try:
            while time.monotonic() - t0 < 60:
                chunk = ss.recv(65536)
                if not chunk:
                    break
                received += len(chunk)
        except (ConnectionResetError, ssl.SSLError, OSError):
            killed_at = round(time.monotonic() - t0, 1)
        ss.close()
        if killed_at:
            print(f"  L3：{killed_at}s 时被掐（传了 {received//1024}KB）")
            print("  → 结论：流量模式敏感，靠轮换解决")
            return {"level": "L3", "verdict": "traffic_sensitive",
                    "killed_at_s": killed_at}
        print(f"  L3：60s 存活（传了 {received//1024//1024}MB）")
        print("  → 结论：该 IP 当前不敏感")
        return {"level": "L3", "verdict": "not_sensitive"}
    except Exception as e:
        print(f"  L3 异常：{str(e)[:60]}")
        return {"level": "L3", "verdict": "error"}


# ---------------------------------------------------------------- 运营商 & git

CARRIER_ASN = {
    "4134": "CT", "4812": "CT", "4809": "CT", "134774": "CT",
    "4837": "CU", "9929": "CU", "17621": "CU", "17622": "CU", "17623": "CU", "4808": "CU",
    "9808": "CM", "24400": "CM", "24445": "CM", "56040": "CM", "56041": "CM",
    "56042": "CM", "56044": "CM", "56046": "CM", "56047": "CM", "56048": "CM",
}


def _carrier_from_text(text):
    t = text or ""
    for asn, isp in CARRIER_ASN.items():
        if f"AS{asn} " in t + " " or f"AS{asn}," in t:
            return isp
    if "联通" in t or "Unicom" in t or "UNICOM" in t:
        return "CU"
    if "电信" in t or "Telecom" in t or "TELECOM" in t or "Chinanet" in t or "CHINANET" in t:
        return "CT"
    if "移动" in t or "Mobile" in t or "MOBILE" in t or "CMNET" in t:
        return "CM"
    return None


def detect_carrier(override=None):
    """检测本机出口运营商。返回 (CT/CU/CM/CN, 出口 IP, 出口国家代码)。

    ip-api 失败时依次换 ipinfo.io、ip.sb；都认不出时返回 "CN"（不再输出 "?"）。
    --carrier 只覆盖运营商，出口国家照样检测：开着 VPN 时国家不是 CN，结果不回传订阅器。
    """
    sources = [
        ("http://ip-api.com/json/?fields=isp,org,as,query,countryCode",
         lambda d: (" ".join(str(d.get(k, "") or "") for k in ("as", "isp", "org")), d.get("query"), d.get("countryCode"))),
        ("https://ipinfo.io/json",
         lambda d: (str(d.get("org", "") or ""), d.get("ip"), d.get("country"))),
        ("https://api.ip.sb/geoip",
         lambda d: (f"AS{d.get('asn', '')} {d.get('isp', '')} {d.get('organization', '')}", d.get("ip"), d.get("country_code"))),
    ]
    egress = None
    country = None
    for url, pick in sources:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cf-pick/3.7"})
            with urllib.request.urlopen(req, timeout=8) as r:
                text, ip, cc = pick(json.load(r))
            egress = egress or ip
            country = country or (str(cc).upper() if cc else None)
            isp = _carrier_from_text(text)
            if isp:
                return (override.upper() if override else isp), egress, country
        except Exception:
            continue
    return (override.upper() if override else "CN"), egress, country


def local_ipv6():
    """本机出口用的 IPv6 地址（UDP connect 不发包，只让系统选路由）。没有公网 v6 返回 None。"""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2400:3200::1", 53))
        addr = s.getsockname()[0]
        s.close()
        ip = ipaddress.ip_address(addr.split("%")[0])
        return str(ip) if ip.is_global else None
    except Exception:
        return None


def has_ipv6():
    """IPv6 连通性：先看本机有没有公网 v6，再连国内/CF 端点，任一通就算有。

    以前只连谷歌和 Cloudflare 的 DNS（443），国内一个被墙一个常被重置，有 v6 也会误判没有。
    """
    if not local_ipv6():
        return False
    endpoints = [
        ("2400:3200::1", 53),          # 阿里 DNS
        ("240c::6666", 53),            # 下一代互联网 DNS
        ("2606:4700::6810:1", 443),    # Cloudflare 边缘（就是要测的那类地址）
        ("2606:4700:4700::1111", 443), # Cloudflare DNS
    ]
    for host, port in endpoints:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((host, port))
            s.close()
            return True
        except Exception:
            continue
    return False


def git_auto_push(top_count, colo, carrier="CN", extra=""):
    """跑完自动 git add/commit/push。"""
    def run(cmd, timeout=60):
        return subprocess.run(cmd, capture_output=True, timeout=timeout)

    # 先确认在 git 仓库里（否则后面的空输出会被误判为"无变化"）
    try:
        top = run(["git", "rev-parse", "--show-toplevel"], timeout=10)
        if top.returncode != 0:
            print("⚠️ 当前目录不是 git 仓库，跳过 push")
            return False
    except Exception:
        print("⚠️ git 不可用，跳过 push")
        return False

    try:
        r = run(["git", "config", "user.email"], timeout=10)
        if r.returncode != 0 or not r.stdout.strip():
            run(["git", "config", "user.email", "cf-pick@termux.local"], timeout=10)
            run(["git", "config", "user.name", "cf-pick"], timeout=10)
            print("ℹ️ 已自动配置 git 身份")
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

    try:
        st = run(["git", "status", "--porcelain", "best-ips.txt", "best-ips.json"],
                 timeout=30)
        if st.returncode != 0:
            print("⚠️ git status 失败")
            return False
        if not st.stdout.strip():
            if commits_ahead(run) > 0:
                print("ℹ️ 结果无变化，但有之前没推上去的提交")
                return push_with_retry(run)
            print("ℹ️ 结果无变化，跳过 push")
            return True
    except Exception:
        pass

    msg = f"update {time.strftime('%Y-%m-%d %H:%M')}: {top_count} IPs ({colo}/{carrier}) {extra}".strip()
    try:
        cm = run(["git", "commit", "-m", msg], timeout=30)
        if cm.returncode != 0:
            err = cm.stderr.decode("utf-8", "ignore")[:200]
            print(f"⚠️ git commit 失败：{err}")
            return False
        local_sha = run(["git", "rev-parse", "HEAD"],
                        timeout=10).stdout.decode().strip()[:8]
        print(f"ℹ️ 本地 commit：{local_sha}")

        return push_with_retry(run)
    except Exception as e:
        print(f"⚠️ push 异常：{e}")
    print("  请手动执行：git push")
    return False


# 国内直连 GitHub 时通时不通：每次 push 限时、慢速自动断开，失败重试；
# 还不行就等你开 VPN（每 10 秒探一次，最多 5 分钟）；最后没推上去的，下次运行开头补推。
PUSH_ATTEMPTS = 3
PUSH_TIMEOUT = 45
WAIT_SECONDS = 300
WAIT_STEP = 10
# 30 秒内速度低于 1KB/s 就放弃这次连接，不再干等到超时
GIT_NET = ["-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=30"]


def _git_run(cmd, timeout=60):
    return subprocess.run(cmd, capture_output=True, timeout=timeout)


def commits_ahead(run=_git_run):
    """本地比远端多几个提交（没推上去的）。查不到上游返回 0。"""
    try:
        r = run(["git", "rev-list", "--count", "@{u}..HEAD"], timeout=10)
        return int(r.stdout.decode().strip() or 0) if r.returncode == 0 else 0
    except Exception:
        return 0


def _push_once(run, timeout=PUSH_TIMEOUT):
    try:
        r = run(["git", *GIT_NET, "push"], timeout=timeout)
        if r.returncode == 0:
            return True, ""
        return False, r.stderr.decode("utf-8", "ignore").strip().splitlines()[-1:] or [""]
    except subprocess.TimeoutExpired:
        return False, [f"{timeout} 秒没推完"]


def github_reachable(run=_git_run, timeout=15):
    try:
        return run(["git", *GIT_NET, "ls-remote", "--heads", "origin"], timeout=timeout).returncode == 0
    except Exception:
        return False


def push_with_retry(run=_git_run, wait=True, attempts=PUSH_ATTEMPTS):
    for attempt in range(1, attempts + 1):
        print(f"⏫ 正在推送到 GitHub（第 {attempt}/{attempts} 次）…", flush=True)
        ok, err = _push_once(run)
        if ok and commits_ahead(run) == 0:
            print("✅ 已 push 到仓库")
            return True
        print(f"  没推上去：{err[0] if err else '远端没更新'}", flush=True)
        if attempt < attempts:
            time.sleep(5 * attempt)
    if wait:
        print(f"📶 直连 GitHub 不通。现在可以打开 VPN（测速已经结束），我每 {WAIT_STEP} 秒试一次，最多等 {WAIT_SECONDS // 60} 分钟；"
              "Ctrl+C 可跳过，下次运行会自动补推。", flush=True)
        deadline = time.time() + WAIT_SECONDS
        try:
            while time.time() < deadline:
                time.sleep(WAIT_STEP)
                if github_reachable(run):
                    ok, err = _push_once(run)
                    if ok and commits_ahead(run) == 0:
                        print("✅ 已 push 到仓库")
                        return True
                left = int(deadline - time.time())
                print(f"  还没通，再等 {max(left, 0)} 秒", flush=True)
        except KeyboardInterrupt:
            print("\n⏭️ 已跳过等待")
    print("⚠️ 这次没推上去，结果已提交到本地，下次运行开头会自动补推（也可以手动 git push）")
    return False


def push_pending():
    """运行开头补推上次没推上去的提交（只试，不等）。"""
    n = commits_ahead()
    if n <= 0:
        return
    print(f"ℹ️ 上次有 {n} 个提交没推上去，先补推")
    # 只试一次，别拖住测速；不通就留到这次跑完再推
    push_with_retry(wait=False, attempts=1)


def _l1_probe(ip):
    """L1 单 IP：3 探针，返回 (ip, worst, loss, jitter) 或 None。"""
    lats = []
    fails = 0
    for _ in range(3):
        lat = tcp_ping(ip, timeout=2)  # 超时 3→2s，失败更快
        if lat is None:
            fails += 1
        else:
            lats.append(lat)
        time.sleep(0.12)
    if not lats:
        return None
    loss = fails / 3.0
    if loss > 0.5:
        return None
    worst = max(lats)
    if worst >= 1.0:
        return None
    jitter = statistics.pstdev(lats) if len(lats) > 1 else 0.0
    return (ip, worst, loss, jitter)


def _l2_trace(args):
    """L2 单 IP：trace，返回 (ip, lat, loss, jitter, colo, loc) 或 None。"""
    ip, lat, loss, jitter, sni = args
    tr = fetch_trace(ip, sni)
    if not tr or tr.get("_error"):
        return None
    if tr.get("_blocked"):
        return None
    return (ip, lat, loss, jitter, tr.get("colo", "?"), tr.get("loc", "?"))


def _l3_geo(args):
    """L3 单 IP：Geo + proxy 检查。

    返回 (ip, lat, loss, jitter, colo, country, is_proxy) 或 None。
    修复：只用 ip-api 判 IP 归属地，不再用 trace loc。
    proxy=true 不淘汰，只标记（软降权在评分时做）。
    """
    ip, lat, loss, jitter, colo, _loc = args
    is_cn, country, is_proxy = check_geo(ip)
    if is_cn:
        return None
    return (ip, lat, loss, jitter, colo, country, is_proxy)


def phase1_funnel(family, count, top_n, sni=SPEED_SNI, conn=None, use_geo=False):
    """Phase 1：并发快漏斗（智能采样）。返回候选列表。"""
    fam_name = f"IPv{'6' if family == 6 else '4'}"
    print(f"\n{'='*50}\nPhase 1 [{fam_name}]：采样 {count} → 并发漏斗\n{'='*50}")
    ips = sample_ips(family, count, conn)
    print(f"采样 {len(ips)} 个")

    # L1: 并发 TCP 3探针
    lat_ok = []
    with ThreadPoolExecutor(max_workers=CONC_L1) as ex:
        futs = {ex.submit(_l1_probe, ip): ip for ip in ips}
        for fu in as_completed(futs):
            r = fu.result()
            if r:
                lat_ok.append(r)
    lat_ok.sort(key=lambda x: (x[2], x[1]))
    print(f"L1 TCP 3探针（{CONC_L1}并发）：{len(lat_ok)}")
    if not lat_ok:
        return []

    # L2: 并发 trace
    colo_ok = []
    with ThreadPoolExecutor(max_workers=CONC_L2) as ex:
        futs = {ex.submit(_l2_trace, (ip, lat, loss, jit, sni)): ip
                for ip, lat, loss, jit in lat_ok[:80]}
        for fu in as_completed(futs):
            r = fu.result()
            if r:
                colo_ok.append(r)
    print(f"L2 trace（{CONC_L2}并发）：{len(colo_ok)}")
    if not colo_ok:
        return []

    # L3: Geo。CF 官方段在 Geo 库里恒为 US/CA，默认跳过；--geo 开启
    geo_ok = []
    if use_geo:
        with ThreadPoolExecutor(max_workers=CONC_L3) as ex:
            futs = {ex.submit(_l3_geo, t): t[0] for t in colo_ok}
            for fu in as_completed(futs):
                r = fu.result()
                if r:
                    geo_ok.append(r)
        print(f"L3 Geo非CN（{CONC_L3}并发）：{len(geo_ok)}")
    else:
        geo_ok = [(ip, lat, loss, jit, colo, "?", False)
                  for ip, lat, loss, jit, colo, _loc in colo_ok]
        print(f"L3 Geo：跳过（CF 官方段，--geo 可开启）")
    if not geo_ok:
        return []
    # 按（丢包, 延迟, 抖动）排序再取测速候选，不再按完成顺序随机取
    geo_ok.sort(key=lambda x: (x[2], x[1], x[3]))

    # L4: 测速（2 并发，省流量）
    scored = []
    def _speed_task(t):
        ip, lat, loss, jit, colo, country, is_proxy = t
        mbps = speed_test(ip, sni)
        if mbps > 0:
            return {"ip": ip, "family": family,
                    "latency_ms": round(lat * 1000, 1),
                    "loss_pct": round(loss * 100, 1),
                    "jitter_ms": round(jit * 1000, 1),
                    "mbps": round(mbps, 2), "country": country,
                    "colo": colo, "is_proxy": is_proxy}
        return None

    with ThreadPoolExecutor(max_workers=CONC_L4) as ex:
        futs = {ex.submit(_speed_task, t): t[0] for t in geo_ok[:SPEED_CANDIDATES]}
        for fu in as_completed(futs):
            r = fu.result()
            if r:
                scored.append(r)
    # 状态码诊断
    from collections import Counter
    bad = Counter(v for k, v in SPEED_STATUS.items() if v != 200)
    if bad:
        print(f"  ⚠️ 测速非 200：{dict(bad)}（429=限流，403=被拒，0=连接失败）")
    scored.sort(key=lambda x: -x["mbps"])
    passed = [x for x in scored if x["mbps"] >= SPEED_MIN_MBS]
    if passed:
        top = passed[:top_n]
    else:
        # 一个都没过线：矮子里拔将军，标记低速，不让漏斗空掉
        top = scored[:top_n]
        for x in top:
            x["low_speed"] = True
        if top:
            print(f"  ⚠️ 无 IP 达到 {SPEED_MIN_MBS} MB/s，按速度兜底输出并标记低速")
    print(f"L4 测速（{CONC_L4}并发，测 {min(len(geo_ok), SPEED_CANDIDATES)} 个）："
          f"{len(passed)} 个达标，取 Top {len(top)}")
    for t in top:
        print(f"  {t['ip']} [{t['colo']}] {t['latency_ms']}ms "
              f"丢包{t['loss_pct']}% {t['mbps']}MB/s")
    return top


def parse_sni_list(sni_arg):
    """解析逗号分隔的 SNI 列表。空→默认。"""
    if not sni_arg:
        return [SPEED_SNI]
    return [s.strip() for s in sni_arg.split(",") if s.strip()] or [SPEED_SNI]


def sni_health_check(ip, sni_list, timeout=8):
    """对 IP 测试多个 SNI 的 TLS 握手健康度。

    返回 {sni: ok}。用于发现被 GFW 针对的 SNI。
    """
    out = {}
    for sni in sni_list:
        ok, _, _ = tls_handshake(ip, sni, timeout=timeout)
        out[sni] = ok
    return out


def format_sub_line(x, carrier, port=443):
    """IP:端口#备注。备注示例：CU-SJC-170ms-3.1MB（低速加 -low，复用加 -old）。"""
    ip = x["ip"]
    host = f"[{ip}]" if ":" in ip else ip
    colo = x.get('colo') if x.get('colo') not in (None, '', '?') else 'UNK'
    remark = f"{carrier}-{colo}-{x.get('latency_ms', 0):.0f}ms"
    if x.get("mbps"):
        remark += f"-{x['mbps']:.1f}MB"
    if x.get("low_speed"):
        remark += "-low"
    if x.get("reused"):
        remark += "-old"
    return f"{host}:{port}#{remark}"


def merge_previous(final, min_count=MIN_OUTPUT, path="best-ips.json"):
    """新结果不足 min_count 时，复测上次的 IP，仍可达的追加到末尾。"""
    if len(final) >= min_count:
        return final
    try:
        with open(path) as f:
            old = json.load(f).get("ips", [])
    except Exception:
        return final
    have = {x["ip"] for x in final}
    added = 0
    for x in old:
        if len(final) >= min_count:
            break
        if x.get("ip") in have:
            continue
        lat = tcp_ping(x["ip"], timeout=2)
        if lat is None:
            continue
        x = dict(x)
        x["latency_ms"] = round(lat * 1000, 1)
        x["reused"] = True
        final.append(x)
        have.add(x["ip"])
        added += 1
    if added:
        print(f"  ♻️ 用上次结果补齐 {added} 个仍可达的 IP")
    return final


class _Tee:
    """同时写屏幕和 last-run.log（widget 跑完窗口就关，事后看日志）。"""
    def __init__(self, stream, path):
        self.stream = stream
        self.f = open(path, "w", encoding="utf-8")
    def write(self, data):
        self.stream.write(data)
        try:
            self.f.write(data); self.f.flush()
        except Exception:
            pass
    def flush(self):
        self.stream.flush()
    def isatty(self):
        return self.stream.isatty()


def main():
    try:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "last-run.log")
        sys.stdout = _Tee(sys.stdout, log_path)
        sys.stderr = _Tee(sys.stderr, log_path + ".err")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="cf-pick v3.7 双栈+稳定性+GFW感知")
    ap.add_argument("--colo", default=None,
                    help="已废弃：不再按colo过滤，保留参数仅为兼容")
    ap.add_argument("--count", type=int, default=300,
                    help="每协议栈采样数")
    ap.add_argument("--top", type=int, default=20,
                    help="每协议栈取 Top N 进 burn-in")
    ap.add_argument("--stability", type=int, default=0,
                    help="burn-in 轮数（0=跳过）")
    ap.add_argument("--interval", type=int, default=60,
                    help="burn-in 轮间隔秒数")
    ap.add_argument("--v4-only", action="store_true")
    ap.add_argument("--v6-only", action="store_true")
    ap.add_argument("--probe-trigger", metavar="IP",
                    help="对单个 IP 做触发器探测")
    ap.add_argument("--ai-test", action="store_true",
                    help="对候选做 AI 目标握手测试")
    ap.add_argument("--scene", default="general",
                    choices=["general", "ai", "web", "video"],
                    help="场景：ai=延迟+零丢包优先，video=带宽优先")
    ap.add_argument("--sni", default=None,
                    help="SNI 健康检查用的域名，逗号分隔多个（填你节点的真实域名）。测速始终用 speed.cloudflare.com")
    # --xray-verify 已移除（需真实 UUID，SNI 健康检查已覆盖 80% 价值）
    ap.add_argument("--evening", action="store_true",
                    help="晚高峰复测模式：只对历史 top 做轻量复测")
    ap.add_argument("--geo", action="store_true",
                    help="开启 Geo 归属地检查（默认跳过，CF 官方段恒为非 CN）")
    ap.add_argument("--port", type=int, default=443,
                    help="写入订阅的端口（默认 443）")
    ap.add_argument("--carrier", choices=["CT", "CU", "CM", "ct", "cu", "cm"], default=None,
                    help="手动指定运营商（自动检测失败时用）")
    ap.add_argument("--push", action="store_true")
    ap.add_argument("--force-push", action="store_true",
                    help="出口不在国内（开着 VPN）时也强制 push，默认不推")
    args = ap.parse_args()

    # 触发器探测模式（独立）
    if args.probe_trigger:
        probe_trigger(args.probe_trigger)
        return

    families = []
    if not args.v6_only:
        families.append(4)
    if not args.v4_only:
        families.append(6)
    # v6-only 时不需要 v4
    if args.v6_only:
        families = [6]
    if args.v4_only:
        families = [4]

    if args.push:
        push_pending()

    carrier, egress, egress_country = detect_carrier(args.carrier)
    network_type = detect_network_type()
    # 出口不在国内（多半开着 VPN）：测到的是代理线路，不是本机宽带/5G，不能当国内实测
    egress_cn = egress_country == "CN" if egress_country else None
    print(f"ℹ️ 出口：{carrier} ({egress}, {egress_country or '国家未知'})，网络：{network_type}")
    if egress_cn is False:
        print("⚠️ 出口不在国内，多半开着 VPN。这次结果只写本地，不会 push；关掉 VPN 再跑才是真实线路。")
    if 6 in families and not args.v6_only:
        # 多端点检测本机 v6 连通性（单端点 3 秒判死刑太草率）
        v6_local = has_ipv6()
        if not v6_local:
            print("⚠️ 未检测到 IPv6 连通性，跳过 v6（如确认有 v6 请用 --v6-only 强制）")
            families = [4] if 4 in families else []
    elif args.v6_only:
        print("ℹ️ --v6-only：跳过连通性检测，直接测 v6")

    if not families:
        print("❌ 没有可用的协议栈")
        sys.exit(1)

    # 历史库提前初始化（供智能采样用）
    _conn_early = init_db()

    # Phase 1
    all_candidates = []
    for fam in families:
        cands = phase1_funnel(fam, args.count, args.top, conn=_conn_early,
                              use_geo=args.geo)
        all_candidates.extend(cands)

    _conn_early.close()

    if not all_candidates:
        print("❌ 漏斗无结果")
        sys.exit(1)

    # 纯净度第二层：AI 握手（Top 候选默认执行）
    print(f"\n{'='*50}\n纯净度第二层：AI 目标握手\n{'='*50}")
    for cand in all_candidates:
        r = ai_target_test(cand["ip"])
        cand["ai_targets"] = r
        ok_n = sum(1 for v in r.values() if v)
        cand["ai_ok"] = ok_n
        mark = "✅" if ok_n == len(r) else f"⚠️{ok_n}/{len(r)}"
        print(f"  {cand['ip']} [{cand['colo']}] {mark}")

    # 纯净度第三层：proxy 标记（ipapi.is 已死，用 ip-api proxy 字段）
    # proxy=true → 软降权 ×0.9，不淘汰（有误报可能）
    print(f"\n{'='*50}\n纯净度第三层：proxy 标记\n{'='*50}")
    for cand in all_candidates:
        if cand.get("is_proxy"):
            cand["abuse_clean"] = False
            cand["abuse_detail"] = "proxy=true"
            print(f"  {cand['ip']} ⚠️ proxy 标记 → 降权10%")
        else:
            cand["abuse_clean"] = True
            cand["abuse_detail"] = "clean"

    conn = init_db()

    # AI 目标感知
    ai_results = {}
    if args.ai_test:
        print(f"\n{'='*50}\nAI 目标感知测试\n{'='*50}")
        for c in all_candidates:
            r = ai_target_test(c["ip"])
            ai_results[c["ip"]] = r
            ok_str = "/".join("✅" if v else "❌" for v in r.values())
            print(f"  {c['ip']}: {ok_str}")
            c["ai_targets"] = {k: v for k, v in r.items()}

    # Phase 2+3: burn-in
    final = []
    if args.stability > 0:
        print(f"\n{'='*50}\nPhase 2+3：burn-in {args.stability} 轮\n{'='*50}")
        burn = burn_in(all_candidates, rounds=args.stability,
                       interval=args.interval)
        for c in all_candidates:
            ip = c["ip"]
            score, succ, cv = stability_score(burn[ip])
            c["stability"] = score
            c["success_rate"] = succ
            c["cv"] = cv
            # GFW 敏感标记
            rst_count = sum(1 for r in burn[ip]
                            if r["fail_type"] == "rst_midstream")
            c["gfw_sensitive"] = rst_count > 0
            c["rst_hits"] = rst_count
            # 历史可靠性
            hist = historical_reliability(conn, ip)
            c["history"] = hist
            # 评分：Zeus 扣分制 + zqy857 完整度/新鲜度 + 带宽加成
            # 基础 100，丢包第一（无上限），延迟第二，抖动第三
            s = 100.0
            s -= c.get("loss_pct", 0) * 0.9
            s -= min(45.0, c["latency_ms"] / 1000.0 * 45.0)
            s -= min(20.0, c.get("jitter_ms", 0) / 200.0 * 20.0)
            # 完整度折扣（zqy857）：没测带宽最高 53
            # （这里带宽已测，完整度=1，不打折；保留逻辑供未来）
            # 带宽加成：20MB/s 满分 10 分（AI 够用就行，不主导）
            s += min(10.0, (c["mbps"] / 20.0) ** 0.65 * 10.0)
            # 稳定性加成：burn-in 稳定分换算
            s = s * 0.7 + score * 0.3
            # 新鲜度衰减（zqy857）：历史越老分越低
            if hist is not None:
                # hist 已经是时间衰减后的值，直接融合
                s = s * 0.8 + hist * 0.2
            # GFW 敏感降权（但不直接扔，冷却后可能恢复）
            if c["gfw_sensitive"]:
                s *= 0.85
            # 纯净度第三层：proxy 标记软降权（×0.9，不淘汰）
            if c.get("is_proxy"):
                s *= 0.9
                print(f"    {c['ip']} proxy 标记，降权10%")
            # 纯净度第二层：AI 握手不全过降权（4 个 CF 托管目标）
            ai_ok = c.get("ai_ok", 4)
            if ai_ok < 4:
                s *= (0.6 + 0.1 * ai_ok)  # 3/4→0.9, 2/4→0.8, 1/4→0.7, 0/4→0.6
            c["final_score"] = round(max(0, s), 1)
            # 入库
            record_history(conn, ip, c["family"], c.get("colo", args.colo),
                           carrier, c["latency_ms"], c["mbps"],
                           score > 50, "mixed", score,
                           loss_pct=c.get("loss_pct"), jitter_ms=c.get("jitter_ms"),
                           ai_ok=c.get("ai_ok"), is_proxy=c.get("is_proxy"))
            final.append(c)
        final.sort(key=lambda x: -x["final_score"])
    else:
        # 默认排名引入丢包/抖动扣分（Zeus 式），不再纯按带宽
        for c in all_candidates:
            if args.scene == "ai":
                # AI 场景：延迟+零丢包优先，带宽几乎无关
                s = 100.0
                s -= c.get("loss_pct", 0) * 2.0  # 丢包双倍扣
                s -= min(50.0, c["latency_ms"] / 1000.0 * 50.0)
                s -= min(20.0, c.get("jitter_ms", 0) / 200.0 * 20.0)
                s += min(5.0, (c["mbps"] / 20.0) * 5.0)  # 带宽只加分
            elif args.scene == "video":
                # 视频场景：带宽优先
                s = c["mbps"] * 2.0
                s -= c.get("loss_pct", 0) * 1.0
                s -= min(20.0, c["latency_ms"] / 1000.0 * 20.0)
            else:
                # 通用：Zeus 扣分制
                s = 100.0
                s -= c.get("loss_pct", 0) * 0.9
                s -= min(45.0, c["latency_ms"] / 1000.0 * 45.0)
                s -= min(20.0, c.get("jitter_ms", 0) / 200.0 * 20.0)
                s += min(10.0, (c["mbps"] / 20.0) ** 0.65 * 10.0)
            # proxy 软降权
            if c.get("is_proxy"):
                s *= 0.9
            c["final_score"] = round(max(0, s), 1)
            record_history(conn, c["ip"], c["family"],
                           c.get("colo", args.colo), carrier,
                           c["latency_ms"], c["mbps"], True, "ok", None,
                           loss_pct=c.get("loss_pct"), jitter_ms=c.get("jitter_ms"),
                           ai_ok=c.get("ai_ok"), is_proxy=c.get("is_proxy"))
            final.append(c)
        final.sort(key=lambda x: -x["final_score"])

    conn.close()

    # 输出
    print(f"\n{'='*50}\n最终排名 Top {len(final)}\n{'='*50}")
    for i, c in enumerate(final, 1):
        fam = f"v{c['family']}"
        extra = ""
        if args.stability > 0:
            extra = (f" 稳定{c['stability']} 成功率{c['success_rate']}% "
                     f"CV{c['cv']}%")
            if c["gfw_sensitive"]:
                extra += f" ⚠️GFW敏感×{c['rst_hits']}"
            if c.get("history"):
                extra += f" 历史{c['history']}"
        else:
            # 非 burn-in 模式也显示丢包/抖动
            extra = f" 丢包{c.get('loss_pct',0)}% 抖动{c.get('jitter_ms',0)}ms"
        print(f"  {i}. {c['ip']} [{fam}/{c.get('colo','?')}] {c['mbps']}MB/s "
              f"分{c['final_score']}{extra}")

    # v4/v6 对比
    v4s = [c for c in final if c["family"] == 4]
    v6s = [c for c in final if c["family"] == 6]
    if v4s and v6s:
        print(f"\n📊 v4/v6 对比：")
        if args.stability > 0:
            avg4 = sum(c["stability"] for c in v4s) / len(v4s)
            avg6 = sum(c["stability"] for c in v6s) / len(v6s)
            print(f"  v4 平均稳定性：{avg4:.1f}（{len(v4s)}个）")
            print(f"  v6 平均稳定性：{avg6:.1f}（{len(v6s)}个）")
            if avg6 > avg4 + 10:
                print("  → v6 明显更稳，GFW 对 v6 手下留情")
            elif avg4 > avg6 + 10:
                print("  → v4 更稳")
            else:
                print("  → 两者接近")

    # /24 分散过滤：每 /24 最多 5 个，至少 4 个 /24
    # （深挖结论：GFW 惩罚精确到单 IP，但情报是关联的）
    def diversify(cands, per_24=5, min_nets=4):
        from collections import defaultdict
        by_24 = defaultdict(list)
        for x in cands:
            try:
                net = str(ipaddress.ip_network(x["ip"] + "/24", strict=False))
            except Exception:
                net = "unknown"
            by_24[net].append(x)
        # 按每网段最佳分排序网段
        nets_sorted = sorted(by_24.keys(),
                             key=lambda n: -max(y.get("final_score", 0)
                                                for y in by_24[n]))
        out = []
        for net in nets_sorted:
            # 每段内按分排序，取前 per_24
            seg = sorted(by_24[net],
                         key=lambda y: -y.get("final_score", 0))[:per_24]
            out.extend(seg)
        # 如果网段数不足，说明候选太集中，保留原样并警告
        if len(by_24) < min_nets:
            print(f"  ⚠️ 仅 {len(by_24)} 个 /24，集中度偏高")
        else:
            print(f"  ✅ 分散到 {len(by_24)} 个 /24，每段 ≤{per_24} 个")
        # 保持全局按分排序
        out.sort(key=lambda x: -x.get("final_score", 0))
        return out

    final = diversify(final)

    # --evening 晚高峰复测（只对 Top N 做 TCP+抖动轻量复测）
    if args.evening and final:
        import datetime
        hour = datetime.datetime.now().hour
        is_peak = 20 <= hour <= 23
        print(f"\n{'='*50}\n晚高峰复测（当前 {hour} 点，"
              f"{'高峰' if is_peak else '非高峰'}）\n{'='*50}")
        for x in final[:10]:
            # 轻量：3 探针 TCP
            lats = []
            for _ in range(3):
                lat = tcp_ping(x["ip"], timeout=2)
                if lat:
                    lats.append(lat)
                time.sleep(0.1)
            if lats:
                import statistics
                new_lat = max(lats) * 1000
                new_jit = (statistics.pstdev(lats) * 1000
                           if len(lats) > 1 else 0)
                old_lat = x["latency_ms"]
                # 高峰降级超过 50% 则标记
                if new_lat > old_lat * 1.5:
                    x["peak_degraded"] = True
                    print(f"  {x['ip']} ⚠️ 高峰降级：{old_lat:.0f}→{new_lat:.0f}ms")
                else:
                    x["peak_degraded"] = False
                    print(f"  {x['ip']} ✅ 高峰稳定：{new_lat:.0f}ms")
                x["peak_latency_ms"] = round(new_lat, 1)
            else:
                x["peak_degraded"] = True
                print(f"  {x['ip']} ❌ 高峰不可达")
        # 降级的排后面
        final.sort(key=lambda x: (x.get("peak_degraded", False),
                                  -x.get("final_score", 0)))

    # 多 SNI 健康检查（如果用户提供了多个 SNI）
    sni_list = parse_sni_list(args.sni)
    if len(sni_list) > 1 and final:
        print(f"\n{'='*50}\nSNI 健康检查（{len(sni_list)} 个 SNI，Top {min(10, len(final))}）\n{'='*50}")
        for x in final[:10]:
            health = sni_health_check(x["ip"], sni_list)
            ok_n = sum(1 for v in health.values() if v)
            x["sni_ok"] = ok_n
            x["sni_total"] = len(sni_list)
            mark = "✅" if ok_n == len(sni_list) else f"⚠️{ok_n}/{len(sni_list)}"
            print(f"  {x['ip']} {mark}")
            if ok_n < len(sni_list):
                bad = [s for s, ok in health.items() if not ok]
                print(f"    失败 SNI：{', '.join(bad[:3])}")

    # 输出不足时，用上次结果里仍可达的 IP 补齐（订阅不突然变空/大换血）
    final = merge_previous(final, MIN_OUTPUT)

    # 写文件：订阅生成器标准格式 IP:端口#备注，IPv6 加方括号
    with open("best-ips.txt", "w") as f:
        for x in final:
            f.write(format_sub_line(x, carrier, args.port) + "\n")
    # 结构化回传，每个 IP 带运营商、网络类型、测量时间，订阅器可区分手机蜂窝与家宽数据
    measured_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    for x in final:
        x.setdefault("carrier", carrier)
        x.setdefault("network_type", network_type)
        x.setdefault("measured_at", measured_at)
    with open("best-ips.json", "w") as f:
        json.dump({"carrier": carrier,
                   "network_type": network_type,
                   "egress_hash": (hashlib.sha256(egress.encode()).hexdigest()[:12] if egress else None),
                   "egress_country": egress_country,
                   "egress_cn": egress_cn,
                   "version": "3.7",
                   "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   "ips": final}, f, indent=2, ensure_ascii=False)
    print(f"\n✅ 已写入 best-ips.txt/json（{len(final)} 个）")

    if args.push and egress_cn is False and not args.force_push:
        print("⏭️ 出口不在国内，跳过 push（确实要推就加 --force-push）")
    elif args.push:
        top_colo = final[0].get("colo") or "unknown" if final else "unknown"
        git_auto_push(len(final), top_colo, carrier, extra="v3.7")


if __name__ == "__main__":
    main()
