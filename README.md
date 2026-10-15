# cf-termux-pick

Termux 上的 Cloudflare 优选 IP 扫描器。单文件、零依赖，手机上直接跑。

## 定位

我是 AI 重度用户，需要**干净、稳定**的 CF IP。不锁机房，不看广告看疗效——只看三层纯净度。

## 快速开始

```bash
# 最常用：AI 场景，一键跑完自动推送
python cf-pick.py --scene=ai --push

# 带你的 10 个 SNI 做健康检查
python cf-pick.py --scene=ai --sni=sni1.com,sni2.com --push

# 晚高峰复测（21-23点跑）
python cf-pick.py --scene=ai --evening --push
```

## 核心设计

### 并发漏斗（v2.3）

| 层 | 并发 | 说明 |
|---|---|---|
| L1 TCP 3探针 | 20 | 最便宜，手机安全值 |
| L2 TLS trace | 10 | 耗 CPU，防自干扰 |
| L3 Geo 检查 | 5 | 默认跳过，`--geo` 开启 |
| L4 测速 | 2 | 最耗流量 |

100 采样约 40 秒，300 采样约 2 分钟。

### 智能采样（v2.4）

- 60% 从历史优质 /24 邻域采样（SQLite 学习）
- 40% 随机探索（发现新富矿）
- 越跑越准，冷启动退化为纯随机

### 纯净度三层（v2.2/v2.5）

1. **Geo 一致性**：ip-api 查归属地，非 CN 才留
2. **AI 握手**：只测 CF 托管域名（openai/groq/mistral/openrouter）
3. **Proxy 标记**：ip-api 的 `proxy` 字段，true 则 ×0.9 软降权

### /24 分散（v2.5）

每 /24 最多 5 个，至少 4 个网段。GFW 惩罚精确到单 IP，但情报是关联的——别把鸡蛋放一个篮子。

### SNI 健康检查（v2.7）

`--sni` 支持逗号分隔多值，Top 10 自动测每个 SNI 的 TLS 握手，一眼看出哪个 SNI 被针对。

### 场景化评分（v2.6）

```bash
--scene=ai     # 延迟+零丢包优先（AI API 流式场景）
--scene=video  # 带宽优先
--scene=web    # 通用均衡（默认）
--scene=general
```

AI 场景下，5Mbps 零丢包 > 100Mbps 偶发丢包。

### 晚高峰复测（v2.9）

```bash
--evening  # Top 10 轻量 TCP 复测，标记高峰降级 IP
```

白天测的好 IP，晚上可能降级。21-23 点跑这个。

## 参数全表

| 参数 | 默认 | 说明 |
|---|---|---|
| `--count` | 300 | 每协议栈采样数 |
| `--top` | 20 | 取 Top N |
| `--scene` | general | ai/web/video/general |
| `--sni` | speed.cloudflare.com | 测试 SNI，逗号分隔多值 |
| `--evening` | - | 晚高峰复测模式 |
| `--stability` | 0 | burn-in 轮数（0=跳过） |
| `--interval` | 60 | burn-in 轮间隔秒数 |
| `--ai-test` | - | AI 目标握手测试 |
| `--v4-only` / `--v6-only` | - | 只测 v4/v6 |
| `--probe-trigger IP` | - | 单 IP 触发器探测 |
| `--geo` | - | 开启 Geo 归属地检查（默认跳过） |
| `--port` | 443 | 写入订阅的端口 |
| `--carrier` | 自动 | 手动指定运营商 CT/CU/CM（自动检测失败时用） |
| `--push` | - | 自动 commit+push，带远端 SHA 验证 |

## 输出

- `best-ips.txt` — `IP:443#CU-SJC-170ms-3.1MB` 格式（IPv6 带方括号），preferred-sub-generator 自动拉取；`-low` = 低速兜底，`-old` = 上次结果复用
- `best-ips.json` — 完整结果（含评分、分项、SNI 健康）
- `ip_history.db` — SQLite 历史库（时段/网络/分项全记录）

## 自动驾驶

```bash
# 手机跑完自动推送
python cf-pick.py --scene=ai --push
    ↓
# 订阅器每 6 小时自动拉取 best-ips.txt → 更新 KV
```

`--push` 带远端 SHA 验证，推成功才报成功，不说谎。

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

桌面添加 Termux:Widget，点一下就跑。

## 安全红线

- 只扫描 Cloudflare 官方公布的 IP 段（白名单写死）
- 只碰 443 端口
- 测速并发 2，省流量
- 不存密钥，不传隐私

## 版本历史

- **v3.3**：IPv4 随机采样改为在全部 /24 里不放回均匀抽（每个 /24 最多 1 个）；运营商检测换三个来源按 ASN 识别，认不出时标 `CN` 不再输出 `?`，可用 `--carrier` 指定；`best-ips.json` 每个 IP 带运营商、网络类型（wifi/cellular）、测量时间；`--sni` 说明改正（只用于 SNI 健康检查，测速始终走 speed.cloudflare.com）；版本号统一
- **v3.2**：测速修复（10MB + Referer + 状态码诊断）、L4 按丢包/延迟排序取 30、动态门槛 0.3 MB/s + 兜底、Geo 默认跳过、输出订阅标准格式、不足 10 个用上次结果补齐
- **v3.0**：历史库 schema 升级（时段/网络/分项）
- **v2.9**：GeoIP 三级降级，`--evening` 实现
- **v2.8**：默认 300 采样，移除 xray-verify
- **v2.7**：多 SNI 支持
- **v2.6**：L3 batch、L4 早退、`--scene`、`--sni`
- **v2.5**：/24 分散、CF 托管 AI 目标
- **v2.4**：智能采样
- **v2.3**：并发漏斗
- **v2.2**：去 SJC 锁，纯净度三层
- **v2.1**：三探针、丢包/抖动评分
- **v2.0**：双栈、burn-in、GFW 感知
