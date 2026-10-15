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

# 测速目标
SPEED_URL_PATH = "/__down"
SPEED_SNI = "speed.cloudflare.com"

# AI 目标感知测试（只做 TLS 握手，不调 API、不耗 key）
AI_TARGETS = [
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
]

DB_PATH = "ip_history.db"


# ---------------------------------------------------------------- 基础工具

def sample_ips(family, count):
    """整数范围随机采样（不枚举，避免大网段内存爆炸）。"""
    ranges = CF_V4 if family == 4 else CF_V6
    out = set()
    nets = [ipaddress.ip_network(c) for c in ranges]
    # 按地址空间大小加权
    weights = [n.num_addresses for n in nets]
    total = sum(weights)
    while len(out) < count:
        r = random.uniform(0, total)
        for net, w in zip(nets, weights):
            r -= w
            if r <= 0:
                # 随机取网段内一个地址（跳过网络地址和广播地址）
                lo = int(net.network_address) + 1
                hi = int(net.broadcast_address) - 1
                if family == 6:
                    hi = int(net.network_address) + net.num_addresses - 1
                ip_int = random.randint(lo, hi)
                out.add(str(ipaddress.ip_address(ip_int)))
                break
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
               f"Connection: close\r\nUser-Agent: cf-pick/2.0\r\n\r\n")
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
    """归属地检查。返回 (is_cn, country)。失败返回 (False, '?')。"""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode"
        with urllib.request.urlopen(url, timeout=timeout) as r:
            d = json.load(r)
            cc = d.get("countryCode", "?")
            return (cc == "CN"), d.get("country", "?")
    except Exception:
        return False, "?"


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
               f"User-Agent: cf-pick/2.0\r\n\r\n")
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
               f"User-Agent: cf-pick/2.0\r\n\r\n")
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
    """对 AI 服务域名做 TLS 握手测试（不调 API）。返回 {domain: ok}。"""
    out = {}
    for dom in AI_TARGETS:
        ok, ftype, _ = tls_handshake(ip, dom, timeout=timeout)
        out[dom] = ok
    return out


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
               f"User-Agent: cf-pick/2.0\r\n\r\n")
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


def git_auto_push(top_count, colo, carrier="?", extra=""):
    """跑完自动 git add/commit/push。"""
    def run(cmd, timeout=60):
        return subprocess.run(cmd, capture_output=True, timeout=timeout)

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


# ---------------------------------------------------------------- 主流程

def phase1_funnel(family, colo, count, top_n, sni=SPEED_SNI):
    """Phase 1：采样 → 四层漏斗。返回候选列表。"""
    fam_name = f"IPv{'6' if family == 6 else '4'}"
    print(f"\n{'='*50}\nPhase 1 [{fam_name}]：采样 {count} → 四层漏斗\n{'='*50}")
    ips = sample_ips(family, count)
    print(f"采样 {len(ips)} 个")

    # L1: TCP 延迟
    lat_ok = []
    for ip in ips:
        lat = tcp_ping(ip, timeout=3)
        if lat is not None and lat < 1.0:
            lat_ok.append((ip, lat))
    lat_ok.sort(key=lambda x: x[1])
    print(f"L1 TCP延迟 <1s：{len(lat_ok)}")
    if not lat_ok:
        return []

    # L2: colo 校验
    colo_ok = []
    for ip, lat in lat_ok[:80]:
        tr = fetch_trace(ip, sni)
        if not tr or tr.get("_error"):
            continue
        if tr.get("colo") == colo:
            colo_ok.append((ip, lat))
    print(f"L2 colo={colo}：{len(colo_ok)}")
    if not colo_ok:
        return []

    # L3: 送中过滤
    geo_ok = []
    for ip, lat in colo_ok:
        is_cn, country = check_geo(ip)
        if not is_cn:
            geo_ok.append((ip, lat, country))
    print(f"L3 非 CN：{len(geo_ok)}")
    if not geo_ok:
        return []

    # L4: 测速
    scored = []
    for ip, lat, country in geo_ok[:30]:
        mbps = speed_test(ip, sni)
        if mbps > 1.0:
            scored.append({"ip": ip, "family": family,
                           "latency_ms": round(lat * 1000, 1),
                           "mbps": round(mbps, 2), "country": country,
                           "colo": colo})
    scored.sort(key=lambda x: -x["mbps"])
    top = scored[:top_n]
    print(f"L4 测速 >1MB/s：{len(scored)}，取 Top {len(top)}")
    for c in top:
        print(f"  {c['ip']} {c['latency_ms']}ms {c['mbps']}MB/s")
    return top


def main():
    ap = argparse.ArgumentParser(description="cf-pick v2.0 双栈+稳定性+GFW感知")
    ap.add_argument("--colo", default="SJC")
    ap.add_argument("--count", type=int, default=200,
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
    v6_local = False
    if 6 in families:
        # 快速检测本机是否有 v6
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(("2606:4700:4700::1111", 443))
            s.close()
            v6_local = True
        except Exception:
            v6_local = False
        if not v6_local:
            print("⚠️ 本机无 IPv6 连通性，跳过 v6")
            families = [f for f in families if f != 4 or True]
            families = [4] if 4 in families else []

    if not families:
        print("❌ 没有可用的协议栈")
        sys.exit(1)

    # Phase 1
    all_candidates = []
    for fam in families:
        cands = phase1_funnel(fam, args.colo, args.count, args.top)
        all_candidates.extend(cands)

    if not all_candidates:
        print("❌ 漏斗无结果")
        sys.exit(1)

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
            # 综合评分：速度 0.7 + 稳定 0.3（历史作为加成展示）
            speed_norm = min(c["mbps"] / 20.0 * 100, 100)  # 20MB/s 满分
            final_score = round(speed_norm * 0.7 + score * 0.3, 1)
            c["final_score"] = final_score
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
        print(f"  {i}. {c['ip']} [{fam}] {c['mbps']}MB/s "
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

    # 写文件（v4/v6 标注）
    with open("best-ips.txt", "w") as f:
        for c in final:
            f.write(f"{c['ip']}#v{c['family']}-{args.colo}\n")
    with open("best-ips.json", "w") as f:
        json.dump({"colo": args.colo, "carrier": carrier,
                   "version": "2.0",
                   "updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   "ips": final}, f, indent=2)
    print(f"\n✅ 已写入 best-ips.txt/json（{len(final)} 个）")

    if args.push:
        git_auto_push(len(final), args.colo, carrier, extra="v2.0")


if __name__ == "__main__":
    main()
