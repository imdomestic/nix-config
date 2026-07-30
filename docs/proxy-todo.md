# 代理链路待办

2026-07-29 那轮凭据轮换之后剩下的几件事，都不紧急，但每件都有取舍，记在这里
免得下次从头推一遍。

拓扑速记：r5sjp（日本，唯一出口）作为 bridge 主动拨向各 portal 的 `interconn2`；
客户端连 portal 的 `client-in2`，流量经反向隧道从 r5sjp 出去。**r5sjp 只能经
tailscale `100.64.0.16` 访问**，它的公网 IPv6 有防火墙，从外面连不进来。

---

## 1. xmc finalmask（观望）

Xray 的 [PR #6210](https://github.com/XTLS/Xray-core/pull/6210) 加了一个叫 xmc 的
finalmask 传输层，用真实 Minecraft 协议做伪装。作者写它的动机基本就是这套部署：
国内中转机、HTTP/TLS 有备案问题、不想暴露第三方 SNI。它不需要 dest 拨号、不需要
证书、不需要备案——对"江苏家宽 IP 上跑着 www.aliyun.com"这种本就不合理的伪装来说，
换成"家宽上开了个 MC 服"确实更自然。

**当前不采用，三个理由叠加：**

- **要跑 prerelease。** xmc 在 v26.7.11 合入，而 XTLS 从 2026-03 起发布的全是
  prerelease，最后一个正式版是 v26.3.27。nixpkgs 的所有分支（含 master）都停在
  26.3.27——不是落后，是它跟正式版。用 xmc 就得自己 override 这个包（改 `version`
  / `hash` / `vendorHash`）并长期自己维护。
- **已知的认证前 DoS 没修。** [#6505](https://github.com/XTLS/Xray-core/pull/6505)
  是 VarInt 遇负值死循环，认证之前就能触发；[#6497](https://github.com/XTLS/Xray-core/pull/6497)
  是叠在 REALITY 下面时 panic——而那正是会用到的组合。两个 PR 都是 closed 但
  **merged=False**，且 `transport/internet/finalmask/xmc/` 至今只有两个提交
  （`35387572` 初始加入、`6ab123bf` 加 padding/keep-alive），修复没有以任何形式进代码。
- **客户端支持面未确认。** 如果只有 Xray-core 实现，那它只能用在 r5sjp↔portal
  这条服务器对服务器的链路上；手机/电脑客户端（Egern、mihomo）用不了。这一点没查完。

**重新评估的触发条件：** #6505 那类问题真的修掉，且进了 XTLS 的正式版（不是
prerelease），且 nixpkgs 跟上。届时先只在 `interconn2`（唯一跨境的那段）上试，
`client-in2` 是境内到境内，按
[A Wall Behind A Wall](https://gfw.report/publications/sp25/en/)（IEEE S&P 2025）
GFW 不检查境内互通流量，那一段换不换伪装意义不大。

## 2. v6 节点从高端口搬到 443

已实测**电信不封 IPv6 入站 443**（从外部直连 `r5s.imdomestic.com:443` 成功）。
r5s / r6s / rpi4 / r5sjp 都是纯 v6，可以把 `interconn2` 从 2444 搬到 443，同时
消掉 xray 那条 `REALITY: Listening on non-443 ports` 告警。

优先搬 `interconn2` 而不是 `client-in2`——r5sjp 拨进来这一跳是跨境的，才是 GFW
看得到的那段。h610 是 IPv4 且 443 入站被电信劫持（TCP 能 SYN-ACK 但不回数据），
搬不了。

需要 portal 的监听端口和 r5sjp 的拨号端口同步改，没有只加不改的路径。

## 3. r2s

长期离线，已从 r5sjp 摘掉 bridge/outbound，也从 dae 的 `im` 组移除。
`nixos/hosts/r2s/system.nix` 里**仍是泄露的那套凭据**，所以它一旦重新上线就会
再次对外提供公开仓库里那个 UUID。

而且 `r2s.imdomestic.com` 现在解析到的多半已经不是它——那个地址 TCP 能建连但
SSH 和 TLS 都不响应，住宅 v6 前缀轮换后落到别人设备上了。**先确认这台机器和这条
DNS 记录的实际状态，再决定是补做轮换还是干脆摘掉。**

补做的步骤：`ssh-keyscan -t ed25519` 拿 host key → `ssh-to-age` → 加进
`.sops.yaml` 的 `host_r2s` 和 creation_rules → 建 `secrets/hosts/r2s.yaml` →
照 rpi4/r5s/r6s 同样处理。

## 4. 死代码里的旧凭据（已解决）

`nixos/modules/singbox/default.nix` 里原先还留着那个泄露的 UUID 和公钥（连同
已下线的 54321 端口和 `www.microsoft.com` 这个 sni）。2026-07-31 重写该模块时
一并清掉了，现在全部凭据从 `secrets/clients/imdomestic.yaml` 经 sops 读入。

## 5. sing-box 迁移（已回滚，两个问题都没解决）

2026-07-31 凌晨在 r6s 上试了一次 dae -> sing-box，**两种 `auto_redirect` 取值
各自坏在不同的地方**，最后回滚到 dae。`nixos/modules/singbox` 已经重写好并且
凭据进了 sops（`secrets/clients/imdomestic.yaml`，加密给全部 admin + 全部
host），r6s 的 import 已改回 dae。重新试之前必须先解决下面两条。

**`auto_redirect = true`（上游推荐值）：LAN 正常，路由器自己的 IPv4 全挂。**
它对本机发出的 TCP 是在 nat output 链里 `redirect to :<port>`，内核把目的地址
改写成 127.0.0.1 从 lo 投递，源地址仍是 WAN 地址。电信 PPPoE 给 r6s 的是
CGNAT 地址 `100.84.115.12`，而 tailscale 在 filter INPUT 挂了

    ip saddr 100.64.0.0/10 iifname != "tailscale0" drop

于是每个重定向到 lo 的 SYN 都被丢掉——没有 RST，没有日志，只在 lo 上看到
SYN 重传。IPv6 不受影响（tailscale 对应规则用的是 `fd7a:115c:a1e0::/48`），
LAN 转发也不受影响（prerouting 的 redirect 源是 192.168.22.x）。所以症状精确
落在「只有路由器自己上不了 v4」这个很迷惑的组合上。

注意这已经是同一个网络里第二次撞 `100.64.0.0/10`：shanghai 那台的注释写着
运营商 DHCP 下发的 DNS 也在这个段里，和 tailscale 撞过一次。

想不出干净解法的原因：nftables 里 `accept` 不是终结的，在更早的链里放行没用，
只有 `drop` 终结；而 tailscale 那条规则是它自己管理的链，改了会被覆盖。
`--netfilter-mode=off` 能绕开但要自己接管 tailscale 的转发规则。

**`auto_redirect = false`：TCP 根本不进 tun，全网断。**
实测日志对比（同样约 6 分钟窗口）：

    auto_redirect=true   TCP 1604 条, UDP 5780 条, vless 988 次
    auto_redirect=false  TCP    7 条, UDP 33807 条, vless 123 次

UDP（DNS、tailscale 的 41641）照进不误，TCP 几乎为零。两种模式用的是同一套
`ip rule`，所以差异不在路由层，**具体机制没查清**。另外注意 false 那次
LAN 客户端的 tailscale UDP 也被卷进了 tun（日志里大量
`inbound packet connection to 192.168.22.x:41641`），本来就不该进。

**下次重试的前提：**先在一台不当网关、也不吃 CGNAT 地址的机器上（比如 tank
或 n100）把 `auto_redirect=false` 时 TCP 不进 tun 的机制搞清楚，再回到 r6s。
不要再直接在网关上试——它一挂就是全家断网，而且 r6s 自己就是这台机器上网的
出口，回滚只能靠 tailscale 或者物理接触。

---

## 改代理配置前先跑这几个

```
just check-sops      声明的密钥在 sops 文件里真的存在吗
just check-tunnels   bridge/portal 两端的 reverse-* 域名对得上吗
just check-xray      生成的配置 xray 真的能启动吗
just check-singbox   生成的配置 sing-box 真的能启动吗（在目标机上跑）
```

这三条各自对应一次真实事故：shanghai 自 `e55593c` 起就因为 psk 键名不对而不可
部署却没人发现；shanghai 的 portal 域名被写成了目录名（`reverse-shanghai` vs
`reverse-sh`），两端对不上、隧道静默不通而 `nix eval` 照过；批量改写把三台的
`realitySettings` 变成空块，一样通过求值，直到 xray 启动时报 `empty "password"`
才暴露，r6s 因此宕了半小时。

check-singbox 对应的是 sing-box 1.13 那批「弃用但没删」的写法——旧式 DNS
server、缺 default_domain_resolver——它们不是告警而是启动即 Fatal，配置能求值、
能生成合法 JSON，服务就是起不来。它必须在目标主机上跑：tun/auto_redirect 是
Linux only，在 macOS 上必然失败，本地跑只会得到假阳性。

但要清楚它的边界：**它只能证明配置能被解析和初始化，不能证明流量真的通。**
上面那次断网，`just check-singbox` 是过的。
