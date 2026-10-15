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
