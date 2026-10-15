# cf-termux-pick

Termux 上的 Cloudflare 优选 IP 扫描器。单文件、零依赖，`python` 一条命令直接跑。

## 为什么做这个

我是 AI 重度用户，需要固定美国机房的干净 CF IP。LAX 已被谷歌大面积"送中"（归属地判为中国，AI 服务直接不可用），所以默认锁定 **SJC（圣何塞）**，并自带送中过滤。

## 用法

```bash
# Termux 里
python cf-pick.py                      # 默认：SJC，Top 20
python cf-pick.py --colo SJC --top 30  # 指定机房和数量
python cf-pick.py --samples 100        # 每段采样 100 个（默认 50）
python cf-pick.py --concurrency 20     # 手机流量建议调低并发（默认 50）
python cf-pick.py --dry-run            # 只采样不测试
```

## 原理（四层漏斗）

1. **TCP 延迟初筛** — 只测 443 建连，超 800ms 直接扔
2. **colo 校验** — `/cdn-cgi/trace` 确认落地机房，只要目标 colo
3. **送中过滤** — 双归属地库查 IP，任一报 CN 就扔；同时排掉 1034 错误 IP（真 CF 但不服务你的 zone）
4. **测速** — 只对幸存者下 `speed.cloudflare.com` 测速，0 速度（回源 IP）直接扔

## 输出

- `best-ips.txt` — 纯 `IP:443` 列表，直接喂给订阅器
- `best-ips.json` — 完整结果（延迟/速度/colo/归属地）

## 回传流程

```bash
python cf-pick.py
git add best-ips.txt best-ips.json
git commit -m "update $(date +%F)"
git push
```

订阅器的 GHA 会自动把 `best-ips.txt` 拉进 `manual.txt` 管道。

## 安全红线

- 只扫描 Cloudflare 官方公布的 IPv4 段（白名单写死在代码里），其它输入直接拒绝
- 只碰 443 端口
- 测速并发默认 5，省流量

## 已验证 / 待验证

- ✅ 白名单逻辑（非 CF/国内/非法输入全部拒绝）
- ✅ 四层漏斗逻辑（mock 测试 5 进 1 出）
- ✅ 归属地库查询、trace 机制
- ⏳ 真实 TLS 直连测速需在 Termux 上实测（沙箱出口代理干扰，无法本地验证）


---

## v2.0（2026-10-15）：双栈 + 稳定性 + GFW 感知

### 为什么做 v2.0
单次测速好的 IP，经常用一会就断。根因是 GFW 的**残余审查**：
检测到异常后，对（你的 IP、服务器 IP、端口）三元组持续 120-180 秒注入 RST。
所以 v2.0 的核心是**测稳定性，不只测速度**。

### 新增功能
| 功能 | 说明 |
|---|---|
| 双栈采样 | v4（15 段）+ v6（7 段），整数范围采样不爆内存 |
| burn-in | `--stability 5`：5 轮复测，每轮间隔 60s |
| GFW 感知分类 | `rst_midstream`（传输中被掐）→ 冷却 5 分钟，不是扔掉 |
| 稳定性评分 | 成功率 × (1 - 变异系数)，0-100 |
| SQLite 历史库 | `ip_history.db`，时间衰减可靠性（3 天半衰期） |
| AI 目标感知 | `--ai-test`：测到真实 AI 域名的 TLS 握手 |
| 触发器探测 | `--probe-trigger IP`：分辨 SNI 敏感还是流量敏感 |
| v4/v6 对比 | 输出平均稳定性对比 |

### 用法
```bash
# 完整流程（推荐）
python cf-pick.py --stability 5 --ai-test --push

# 只测 v6
python cf-pick.py --stability 5 --v6-only --push

# 触发器探测（单个 IP）
python cf-pick.py --probe-trigger 104.16.132.229
```

### 评分公式
```
最终分 = 速度分(0-100, 20MB/s满分) × 0.7 + 稳定分(0-100) × 0.3
```
