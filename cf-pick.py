#!/usr/bin/env python3
"""
cf-pick.py v2.0 — Cloudflare 优选 IP（双栈 + 稳定性 + GFW 感知）

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
import ipaddress
import json
import random
import socket
import sqlite3
import ssl
import statistics
import subprocess
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

# GFW 残余审查时长：学术实测 120-180 秒，冷却取 300 秒保底
GFW_COOLDOWN = 300

# v2.3 并发配置（手机安全值）
CONC_L1 = 20  # TCP 握手：最便宜
CONC_L2 = 10  # TLS trace：耗 CPU
CONC_L3 = 5   # Geo API：ip-api 限流 45/分钟
CONC_L4 = 2   # 测速：最耗流量

# 测速目标
SPEED_URL_PATH = "/__down"
SPEED_SNI = "speed.cloudflare.com"

# AI 目标感知测试（只做 TLS 握手，不调 API、不耗 key）
# v2.5：只测 CF 托管的 AI 域名（深挖结论：anthropic/google 不在 CF 上，测了必挂）
AI_TARGETS = [
    "api.openai.com",     # CF
    "api.groq.com",       # CF
    "api.mistral.ai",     # CF
    "openrouter.ai",      # CF
]

DB_PATH = "ip_history.db"


# ---------------------------------------------------------------- 基础工具

def get_good_neighborhoods(conn, family=4, min_score=60, days=7, limit=20):
    """从历史库提取优质 /24 网段（v2.4 智能采样）。

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
    """整数范围随机采样（v2.4：60% 优质邻域 + 40% 随机探索）。

    conn=None 时退化为纯随机（冷启动）。
    """
    ranges = CF_V4 if family == 4 else CF_V6
    out = set()

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

    # 随机部分：补足剩余
    nets = [ipaddress.ip_network(cidr) for cidr in ranges]
    weights = [n.num_addresses for n in nets]
    total = sum(weights)
    target = count - len(out)
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
               f"Connection: close\r\nUser-Agent: cf-pick/2.5\r\n\r\n")
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
    """归属地 + 代理标记检查（v2.5：ipapi.is 已死，用 ip-api proxy 字段替代）。

    返回 (is_cn, country, is_proxy)。失败返回 (False, '?', False)。
    """
    try:
        url = (f"http://ip-api.com/json/{ip}"
               f"?fields=status,country,countryCode,proxy,hosting")
        with urllib.request.urlopen(url, timeout=timeout) as r:
            d = json.load(r)
        if d.get("status") != "success":
            return False, "?", False
        cc = d.get("countryCode", "?")
        return (cc == "CN"), d.get("country", "?"), bool(d.get("proxy", False))
    except Exception:
        return False, "?", False


def speed_test(ip, sni=SPEED_SNI, seconds=8, timeout=15):
    """测下载速度（MB/s）。失败返回 0。"""
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=sni)
        req = (f"GET {SPEED_URL_PATH}?bytes=25000000 HTTP/1.1\r\n"
               f"Host: {sni}\r\nConnection: close\r\n"
               f"User-Agent: cf-pick/2.5\r\n\r\n")
        ss.sendall(req.encode())
        # 跳过响应头
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = ss.recv(4096)
            if not chunk:
                break
            head += chunk
        body_start = head.split(b"\r\n\r\n", 1)
        received = len(body_start[1]) if len(body_start) > 1 else 0
        t0 = time.monotonic()
        while time.monotonic() - t0 < seconds:
            chunk = ss.recv(65536)
            if not chunk:
                break
            received += len(chunk)
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
               f"User-Agent: cf-pick/2.5\r\n\r\n")
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

def init_db(path=DB_PATH):
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE IF NOT EXISTS history (
        ip TEXT, ts REAL, family INTEGER, colo TEXT, carrier TEXT,
        latency_ms REAL, mbps REAL, ok INTEGER, fail_type TEXT,
        stability REAL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON history(ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON history(ts)")
    conn.commit()
    return conn


def record_history(conn, ip, family, colo, carrier, latency_ms, mbps,
                   ok, fail_type, stability):
    conn.execute(
        "INSERT INTO history VALUES (?,?,?,?,?,?,?,?,?,?)",
        (ip, time.time(), family, colo, carrier, latency_ms, mbps,
         1 if ok else 0, fail_type, stability))
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
    """[v2.5 已废弃] ipapi.is 滥用字段 2026-09 起需 API key，免费版已死。
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
               f"User-Agent: cf-pick/2.5\r\n\r\n")
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

def detect_carrier():
    """检测本机出口运营商。返回 (CT/CU/CM/?, 出口 IP)。"""
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


def has_ipv6():
    """多端点检测 IPv6 连通性。任一成功即判定可用。"""
    test_ips = [
        "2606:4700:4700::1111",  # Cloudflare DNS
        "2001:4860:4860::8888",  # Google DNS
        "2606:4700:4700::1001",  # Cloudflare DNS 备用
    ]
    for tip in test_ips:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((tip, 443))
            s.close()
            return True
        except Exception:
            continue
    return False


def git_auto_push(top_count, colo, carrier="?", extra=""):
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

        push = run(["git", "push"], timeout=120)
        if push.returncode != 0:
            err = push.stderr.decode("utf-8", "ignore")[:200]
            print(f"⚠️ push 失败：{err}")
            print("  请手动执行：git push")
            return False

        # 自证：fetch 后对比远端 SHA，不一致就是没推上去
        run(["git", "fetch", "origin"], timeout=30)
        # 找当前分支的上游
        up = run(["git", "rev-parse", "--abbrev-ref",
                  "--symbolic-full-name", "@{u}"], timeout=10)
        upstream = up.stdout.decode().strip() if up.returncode == 0 else "origin/main"
        remote_sha = run(["git", "rev-parse", upstream],
                         timeout=10).stdout.decode().strip()[:8]
        local_full = run(["git", "rev-parse", "HEAD"],
                         timeout=10).stdout.decode().strip()[:8]
        if local_full == remote_sha:
            print(f"✅ 已 push 到仓库（远端已验证：{remote_sha}）")
            return True
        else:
            print(f"⚠️ push 返回成功，但远端 SHA({remote_sha})≠本地({local_full})，实际没推上去")
            print("  请手动执行：git push")
            return False
    except Exception as e:
        print(f"⚠️ push 异常：{e}")
    print("  请手动执行：git push")
    return False


# ---------------------------------------------------------------- 主流程

def _l1_probe(ip):
    """L1 单 IP：3 探针，返回 (ip, worst, loss, jitter) 或 None。"""
    lats = []
    fails = 0
    for _ in range(3):
        lat = tcp_ping(ip, timeout=2)  # v2.3：超时 3→2s，失败更快
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
    v2.3 修复：只用 ip-api 判 IP 归属地，不再用 trace loc。
    v2.5：proxy=true 不淘汰，只标记（软降权在评分时做）。
    """
    ip, lat, loss, jitter, colo, _loc = args
    is_cn, country, is_proxy = check_geo(ip)
    if is_cn:
        return None
    return (ip, lat, loss, jitter, colo, country, is_proxy)


def phase1_funnel(family, count, top_n, sni=SPEED_SNI, conn=None):
    """Phase 1：并发快漏斗（v2.4 智能采样）。返回候选列表。"""
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

    # L3: 并发 Geo（v2.3 修复：只看 IP 归属地）
    geo_ok = []
    with ThreadPoolExecutor(max_workers=CONC_L3) as ex:
        futs = {ex.submit(_l3_geo, t): t[0] for t in colo_ok}
        for fu in as_completed(futs):
            r = fu.result()
            if r:
                geo_ok.append(r)
    print(f"L3 Geo非CN（{CONC_L3}并发）：{len(geo_ok)}")
    if not geo_ok:
        return []

    # L4: 测速（2 并发，省流量）
    scored = []
    def _speed_task(t):
        ip, lat, loss, jit, colo, country, is_proxy = t
        mbps = speed_test(ip, sni)
        if mbps > 1.0:
            return {"ip": ip, "family": family,
                    "latency_ms": round(lat * 1000, 1),
                    "loss_pct": round(loss * 100, 1),
                    "jitter_ms": round(jit * 1000, 1),
                    "mbps": round(mbps, 2), "country": country,
                    "colo": colo, "is_proxy": is_proxy}
        return None

    with ThreadPoolExecutor(max_workers=CONC_L4) as ex:
        futs = {ex.submit(_speed_task, t): t[0] for t in geo_ok[:20]}
        for fu in as_completed(futs):
            r = fu.result()
            if r:
                scored.append(r)
    scored.sort(key=lambda x: -x["mbps"])
    top = scored[:top_n]
    print(f"L4 测速（{CONC_L4}并发）：{len(scored)}，取 Top {len(top)}")
    for t in top:
        print(f"  {t['ip']} [{t['colo']}] {t['latency_ms']}ms "
              f"丢包{t['loss_pct']}% {t['mbps']}MB/s")
    return top


def main():
    ap = argparse.ArgumentParser(description="cf-pick v2.0 双栈+稳定性+GFW感知")
    ap.add_argument("--colo", default=None,
                    help="v2.2已废弃：不再按colo过滤，保留参数仅为兼容")
    ap.add_argument("--count", type=int, default=100,
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
    ap.add_argument("--push", action="store_true")
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

    carrier, egress = detect_carrier()
    print(f"ℹ️ 出口：{carrier} ({egress})")
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
        cands = phase1_funnel(fam, args.count, args.top, conn=_conn_early)
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

    # 纯净度第三层：proxy 标记（v2.5：ipapi.is 已死，用 ip-api proxy 字段）
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
            # v2.1 评分：Zeus 扣分制 + zqy857 完整度/新鲜度 + 带宽加成
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
            # 纯净度第三层：proxy 标记软降权（v2.5：×0.9，不淘汰）
            if c.get("is_proxy"):
                s *= 0.9
                print(f"    {c['ip']} proxy 标记，降权10%")
            # 纯净度第二层：AI 握手不全过降权（v2.5：4 个 CF 托管目标）
            ai_ok = c.get("ai_ok", 4)
            if ai_ok < 4:
                s *= (0.6 + 0.1 * ai_ok)  # 3/4→0.9, 2/4→0.8, 1/4→0.7, 0/4→0.6
            c["final_score"] = round(max(0, s), 1)
            # 入库
            record_history(conn, ip, c["family"], args.colo, carrier,
                           c["latency_ms"], c["mbps"],
                           score > 50, "mixed", score)
            final.append(c)
        final.sort(key=lambda x: -x["final_score"])
    else:
        for c in all_candidates:
            c["final_score"] = c["mbps"]
            record_history(conn, c["ip"], c["family"], args.colo, carrier,
                           c["latency_ms"], c["mbps"], True, "ok", None)
            final.append(c)

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

    # v2.5 /24 分散过滤：每 /24 最多 5 个，至少 4 个 /24
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

    # 写文件（v4/v6 标注 + 真实 colo）
    with open("best-ips.txt", "w") as f:
        for x in final:
            f.write(f"{x['ip']}#v{x['family']}-{x.get('colo', '?')}\n")
    with open("best-ips.json", "w") as f:
        json.dump({"carrier": carrier,
                   "version": "2.5",
                   "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   "ips": final}, f, indent=2)
    print(f"\n✅ 已写入 best-ips.txt/json（{len(final)} 个）")

    if args.push:
        git_auto_push(len(final), args.colo, carrier, extra="v2.5")


if __name__ == "__main__":
    main()
