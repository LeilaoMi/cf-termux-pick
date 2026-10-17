# cf-termux-pick

在 Android 的 Termux 里跑的 Cloudflare 优选 IP 扫描器。一个 Python 文件，只用标准库，在你自己的宽带或 5G 网络上实测，再把结果推回这个仓库，供 [preferred-sub-generator](https://github.com/LeilaoMi/preferred-sub-generator) 当作"国内手机实测"数据源。

当前版本：**v3.7**

---

## 它解决什么问题

云端的测速节点（GitHub Actions、Globalping 等）测不出**你这条线路**上 Cloudflare 的真实表现。cf-pick 直接在手机上测，所以结果反映的就是你当前的运营商、网络类型和时段。

```
手机 Termux（关 VPN）
  │ python cf-pick.py --scene=ai --push
  ▼
best-ips.txt / best-ips.json  ──git push──►  本仓库
                                              │
                         preferred-sub-generator（定时拉取）
                           ├─ Update：best-ips.txt → sources/edge/manual.txt
                           └─ china-probe：读 best-ips.json，只收 egress_cn=true 的结果
                                              │
                                     订阅里带国内机房名的节点
```

---

## 安装

```bash
pkg install python git
git clone https://github.com/LeilaoMi/cf-termux-pick ~/cf-termux-pick
cd ~/cf-termux-pick
```

- 只用到 Python 标准库，不需要 pip 安装任何东西。
- 想用 `--push`，需要先配好 GitHub 的推送凭据（HTTPS token 或 SSH key 都可以）。
- 装了 Termux:API 时，WiFi 和蜂窝判断更准，但不是必须的。

## 快速开始

```bash
# 日常用法：跑完自动推送（记得关 VPN）
python cf-pick.py --scene=ai --push

# 同时检查你节点用的几个 SNI 有没有被针对
python cf-pick.py --scene=ai --sni=a.example.com,b.example.com --push

# 晚高峰复测
python cf-pick.py --scene=ai --evening --push

# 只看结果，不推送
python cf-pick.py --scene=ai
```

### Termux 桌面小部件

```bash
mkdir -p ~/.shortcuts
cat > ~/.shortcuts/cf-pick << 'EOF'
#!/bin/bash
cd ~/cf-termux-pick
git pull --rebase -q
python cf-pick.py --scene=ai --push
EOF
chmod +x ~/.shortcuts/cf-pick
```

在桌面添加 Termux:Widget，点一下就能跑。窗口关了也可以看上次的输出：

```bash
cat ~/cf-termux-pick/last-run.log
```

---

## 一次运行做了什么

### 1. 环境检测

| 项 | 方法 |
|---|---|
| 运营商 | 依次查 ip-api.com、ipinfo.io、ip.sb，按 ASN 或名称识别 CT/CU/CM；都识别不出就标 `CN`，可用 `--carrier` 手动指定 |
| 出口国家 | 同上。不是 CN 就判定为开着 VPN |
| 网络类型 | 先看默认路由走的接口（`wlan` 为 wifi，`rmnet`/`ccmni` 为 cellular），不行再用 `termux-wifi-connectioninfo` |
| IPv6 | 本机要有公网 v6 地址，并且能连上阿里 DNS、240c::6666 或 Cloudflare 中的任意一个；否则跳过 v6 |

### 2. 采样（每个协议栈默认 300 个）

- **IPv4**：在 Cloudflare 官方 15 个网段的所有 /24 里不放回均匀抽样，每个 /24 最多取 1 个。历史库里有好成绩的 /24 时，60% 名额给这些网段的邻近地址，40% 继续随机探索。
- **IPv6**：只在约 95 个实际有应答的 Cloudflare /48 里抽（来自 XIU2/CloudflareSpeedTest）。在官方 /32、/29 整段里随机抽，几乎全是空地址。

### 3. 四层漏斗

| 层 | 并发 | 做什么 | 进入下一层 |
|---|---|---|---|
| L1 TCP | 20 | 3 次 443 握手，记录延迟、丢包、抖动 | 按丢包和延迟取前 80 个 |
| L2 trace | 10 | 访问 `/cdn-cgi/trace`，拿到**国内视角的机房（colo）** | 全部 |
| L3 Geo | 5 | 默认跳过（Cloudflare 网段在 Geo 库里永远显示美国或加拿大），`--geo` 开启 | 按丢包、延迟、抖动取前 30 个 |
| L4 测速 | 2 | 从 `speed.cloudflare.com/__down` 下载 10MB，最长 8 秒，单位 MB/s | 达到 0.3 MB/s 的取 Top N（默认 20） |

如果没有一个 IP 达到 0.3 MB/s，就按速度取前几个并标记 `-low`，保证结果不会是空的。

### 4. 附加检查（只记录，默认不影响排名）

- **AI 握手**：对每个候选 IP 做到 `api.openai.com`、`api.groq.com`、`api.mistral.ai`、`openrouter.ai` 的 TLS 握手，记在 `ai_targets` 和 `ai_ok` 里。只有开启 `--stability` 时才参与扣分。
- **proxy 标记**：取自 ip-api 的 `proxy` 字段，需要开启 `--geo`；标记为 proxy 的分数 ×0.9。

### 5. 评分（`--scene`）

| 场景 | 侧重 |
|---|---|
| `ai` | 丢包双倍扣分，延迟最多扣 50 分，带宽最多只加 5 分 |
| `general`（默认） / `web` | 丢包、延迟、抖动扣分，带宽最多加 10 分 |
| `video` | 带宽为主 |

开启 `--stability N` 后改用 burn-in 评分：多轮复测的稳定分占 30%，7 天历史可靠性占 20%，疑似被 GFW 中途掐断的 ×0.85，AI 握手每少过一个扣 10%。

### 6. 收尾

- **分散**：按 /24 分组，每组最多 5 个，避免集中在一个网段。
- **晚高峰复测**（`--evening`）：对前 10 个 IP 重做 3 次 TCP；延迟比白天高出 50% 以上的标记 `peak_degraded`，排到后面。
- **SNI 健康检查**：`--sni` 给了**两个及以上**域名时，前 10 个 IP 逐个测试每个 SNI 的 TLS 握手，找出被针对的 SNI。
- **补齐**：结果不到 10 个时，复测上次的 IP，仍然连得上的补进来，标记 `-old`。

---

## 推送（`--push`）

- 开始测速前，先把上次没推上去的提交补推一次。
- 出口不在国内（开着 VPN）时**只写本地，不推送**，避免把代理线路的结果当成国内实测；加 `--force-push` 可以强制推送。
- 每次推送限时 45 秒，失败重试 3 次。还是不行就提示你开 VPN（这时测速已经结束，开 VPN 不影响结果），每 10 秒检查一次 GitHub，最多等 5 分钟，按 Ctrl+C 跳过。
- 以远端确认收到为准：本地比远端还多提交，就不报成功。

国内直连 GitHub 时好时坏，推送失败一般是网络问题，不是凭据问题。

---

## 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--scene` | `general` | `ai` / `web` / `video` / `general` |
| `--count` | 300 | 每个协议栈的采样数 |
| `--top` | 20 | 每个协议栈保留几个 |
| `--sni` | — | SNI 健康检查用的域名，逗号分隔，至少 2 个才会检查。测速固定用 `speed.cloudflare.com` |
| `--evening` | — | 晚高峰复测 |
| `--stability` | 0 | burn-in 轮数，0 表示跳过 |
| `--interval` | 60 | burn-in 每轮间隔秒数 |
| `--v4-only` / `--v6-only` | — | 只测 v4 / v6。`--v6-only` 不做 v6 连通性检测 |
| `--geo` | — | 开启 Geo 和 proxy 查询（ip-api 每分钟限 45 次） |
| `--carrier` | 自动 | 手动指定 CT/CU/CM |
| `--port` | 443 | 写进 `best-ips.txt` 的端口 |
| `--push` | — | 自动 commit 和 push |
| `--force-push` | — | 开着 VPN 也推送 |
| `--probe-trigger IP` | — | 单独诊断一个 IP：只握手、少量数据、持续 60 秒传输，看是哪种情况被掐断 |
| `--ai-test` | — | 再单独跑一次 AI 握手并逐个打印（默认流程已经包含 AI 握手） |
| `--colo` | — | 已废弃，保留只是为了兼容 |

---

## 输出文件

### `best-ips.txt`

订阅器直接读取的格式，一行一个：

```
172.64.50.39:443#CU-LAX-166ms-2.9MB
[2606:4700:a:9ff6::1]:443#CU-LAX-165ms-2.5MB
```

备注依次是运营商、L2 测到的机房（测不到写 `UNK`）、延迟、速度。末尾 `-low` 表示低速兜底，`-old` 表示沿用上次的结果。

### `best-ips.json`

```json
{
  "carrier": "CU",
  "network_type": "cellular",
  "egress_country": "CN",
  "egress_cn": true,
  "egress_hash": "e5fb54fa1756",
  "version": "3.7",
  "updated": "2026-10-18T03:23:59",
  "ips": [
    {
      "ip": "172.64.50.39", "family": 4, "colo": "LAX",
      "latency_ms": 166.0, "loss_pct": 0.0, "jitter_ms": 1.6, "mbps": 2.9,
      "ai_targets": { "api.openai.com": false, "api.groq.com": true, "api.mistral.ai": false, "openrouter.ai": true },
      "ai_ok": 2, "final_score": 92.4,
      "carrier": "CU", "network_type": "cellular", "measured_at": "..."
    }
  ]
}
```

- `egress_hash` 是出口 IP 的 SHA-256 前 12 位，文件里不保存明文 IP。
- 订阅器只采用 `egress_cn: true` 的结果，并且 wifi 的权重是 ×1.5，cellular 是 ×1.2。

### 只留在本地的文件（已加入 .gitignore）

- `ip_history.db`：SQLite 历史库，供智能采样和 burn-in 历史评分使用。
- `last-run.log` / `last-run.log.err`：最近一次运行的完整输出。

---

## 已知局限

- **机房由运营商路由决定**：比如联通 5G 测出来基本都是 LAX，这是线路本身的情况，换 IP 也改变不了。
- **测速量很小**：10MB 只够区分"能用"和"不能用"，不能代表大流量下的表现。
- **单点数据**：只代表这台手机此刻的这条线路。订阅器会把它和其他来源一起排序，不会单独依赖它。
- **IPv6 分散效果有限**：分散规则按 /24 分组，对 v6 来说粒度太粗，每个大段最多只保留 5 个。

## 安全边界

- 只扫描 Cloudflare 官方公布的网段（写死在代码里），只连 443 端口。
- AI 握手只做 TLS 握手，不调用任何 API，也不需要密钥。
- 不保存密钥。回传的文件里没有出口 IP 明文。

---

## 版本历史

- **v3.7**：IPv6 只在有应答的 /48 里采样，v6 不再总是空结果；运行输出写入 `last-run.log`
- **v3.6**：IPv6 检测改为先看本机公网地址，不再因为谷歌被墙误判；5G 不再被误标成 wifi
- **v3.5**：推送限时、重试、可以等待开 VPN；没推上去的提交下次自动补推
- **v3.4**：识别出口国家，开着 VPN 时不推送；JSON 增加 `egress_country` / `egress_cn`
- **v3.3**：IPv4 按 /24 均匀采样；运营商识别改用 ASN，并加三个备用来源；每个 IP 记录运营商、网络类型和测量时间
- **v3.2**：测速修复（10MB 加 Referer）、按丢包和延迟取测速候选、低速兜底、不足 10 个时补齐
- **v3.0 及以前**：历史库、晚高峰复测、多 SNI、场景评分、/24 分散、智能采样、并发漏斗、双栈和 burn-in
