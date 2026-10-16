# IPCheck

一个常驻 Windows 桌面的 IP 情报悬浮卡片：实时显示出口 IP、IP 质量、风险度，
并检测本机环境的泄漏与不一致。

Rust 核心 + Tauri v2 + Web 前端。常驻内存约 50MB，安装包约 6MB。

---

## 它能做什么

**看当前出口的真实情况**

- 用 6 个互相独立的端点并发取出口 IP，比对是否一致。不一致本身就是信号——
  通常意味着部分流量没走代理。
- 分别取 IPv4 和 IPv6 出口。IPv6 绕过 IPv4 代理是最常见的意外。
- 手写 STUN 打 UDP 洞，看 UDP 路径是否和 HTTPS 路径同源。WebRTC/QUIC/游戏
  走 UDP，而代理常常只覆盖 TCP。
- DNS 出口与网页出口是否同一国。分流隧道下 DNS 会漏给本地运营商。

**多源交叉的评分**

四个维度分开算，不做简单平均：

| 维度 | 含义 |
|---|---|
| 纯净 | 住宅/移动 > 企业 > 机房；是否命中代理/VPN/Tor 库 |
| 风险 | AbuseIPDB + Scamalytics + IPQS + 黑名单，各源归一化后加权 |
| 可信 | 出口端点是否一致、源是否可用。**一致率是闸门，不是加权项** |
| 一致 | 时区、语言区域、IPv6、DNS 是否都与出口 IP 自洽 |

**源冲突会被显示出来，而不是被平均掉。** 一个源说 5 分、另一个说 90 分，
它不是 47 分——它是冲突，工具会明说，并降低置信权重。

**环境一致性自查**

出口一致性、IPv6 泄漏、UDP 路径、DNS 出口、系统时区 vs IP 时区、
系统语言区域 vs IP 国别。这些是直接观测到的事实，不是从厂商分推断的。

---

## 明确的边界

**不做的：** 本工具不用于、也无法用于规避任何在线服务的区域访问控制。
服务方判断来源依靠账号、支付方式、行为模式等一整套信号，本地悬浮卡片对这些
判断无法给出有意义的结论。

**关于「风控评分」：** Cloudflare / DataDome / Akamai 这类风控系统的内部评分
没有公开接口，任何声称能直接查询的工具都是猜测。本工具通过 IP 信誉库和公开
黑名单做**相关性推断**，并在界面上标明这是推断而非实测，不提供假精度。

**关于黑名单的准确性：** Spamhaus ZEN 包含 PBL 段，而 PBL 收录的是「动态住宅/
移动网段，不应直接发邮件」——地球上每个手机 IP 都在里面。本工具把这类
**策略命中**与真正的滥用命中分开统计，不计入风险分，否则移动网络下所有结果
都是假阳性。

---

## 运行

```
pnpm install
pnpm tauri dev          # 开发
pnpm tauri build        # 打包
```

CLI 与 GUI 共用同一套引擎：

```bash
ipcheck-cli                    # 探测本机，人类可读输出
ipcheck-cli --json             # 输出完整快照 JSON
ipcheck-cli --ip 1.2.3.4       # 查询指定地址
ipcheck-cli --watch 60          # 每 60 秒刷新，只打印变化
```

可选 API Key（无 key 时自动降级，不影响使用）：

```bash
export ABUSEIPDB_KEY=xxx
export SCAMALYTICS_KEY=xxx
export IPQS_KEY=xxx
```

---

## 架构

```
ui/ (TS)  ->  commands  ->  aggregator  ->  { probe, source }  ->  http
                                |
                             score (纯函数，可离线测试)
```

| 模块 | 职责 |
|---|---|
| `probe/egress` | 多端点出口 IP 共识 |
| `probe/stun` | 手写 STUN Binding(UDP 路径) |
| `probe/dns_leak` | DNS 出口一致性 |
| `probe/env_check` | 时区/语言/IPv6 一致性 |
| `source/ipapi` `ipwhois` | 基础画像（免费） |
| `source/dnsbl` | 6 个黑名单（免费无 key） |
| `source/risk` | AbuseIPDB / Scamalytics / IPQS（key 可选） |
| `score` | 四维评分 + 源冲突检测（纯函数） |
| `cache` | 分层 TTL + 每源令牌桶限流 |

**限流设计：** 免费额度很小（AbuseIPDB 1000/天、ip-api 45/分钟）。缓存按类别
分层（画像 5min / 风险 30min / 黑名单 1h），每个源独立令牌桶，某个源 429 只
降级它自己。

---

## 测试

```bash
cd src-tauri && cargo test
```

75 个测试，覆盖评分边界、源冲突、STUN 报文解析（含补齐字节对齐与未知属性
跳过）、出口码分级、缓存过期与限流补充。评分与合并逻辑是纯函数，不需要网络。

---

## 界面实现要点

几个不明显但会踩的地方，记下来免得回退：

- **毛玻璃用 OS 原生 acrylic**（`tauri.conf.json` 的 `windowEffects`），不是 CSS
  `backdrop-filter`。Tauri 透明窗口里，"背后"只有桌面，Web 合成器采样不到，
  CSS 模糊是空操作。
- **展开高度是实测的**，不是常量。检测项、黑名单、数据源数量随每次运行变化，
  任何硬编码高度要么裁内容、要么在窗口底部留下透明死区挡住下层应用的点击。
  `fitWindow()` 读 `#expanded` 的 `scrollHeight`（该元素无高度约束，所以读到的是
  内容自然高度），用 `ResizeObserver` 覆盖 `<details>` 展开等非快照触发的高度变化。
- **点击与拖拽必须区分阈值**。`mousedown` 直接 `startDragging()` 会让每次点击变成
  微小拖动，`click` 永不触发，卡片无法展开。
- **国旗用两字母码而非 emoji**。Windows 的 Segoe UI Emoji 不含区域指示符字形，
  🇨🇳 本来就退化成 "CN"，不如直接按徽章设计。CLI 输出仍用 emoji（终端能渲染）。

---

## 已知取舍

- **ip-api 免费版只有 HTTP**，无 HTTPS。这是免费层的限制，不是疏忽。
- **Scamalytics 的免费 key 路径**没有公开 JSON 契约，只接线了响应形状并做软失败。
- **不做完整 DNS 委派遍历**（那需要自有权威服务器）。当前只做解析器出口比对，
  宁可诚实地窄，也不做假的宽。
