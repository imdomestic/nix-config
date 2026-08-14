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

## 3. r2s（配置已补齐，待设备上线验证）

2026-08-14 已用原 SSH host key 恢复 `host_r2s` 的 SOPS recipient，并新建
`secrets/hosts/r2s.yaml`。WireGuard、DDNS 和全新轮换的 Xray 凭据都改由 SOPS
提供；r5sjp 的 bridge/outbound、共享 DAE 节点以及 mihomo、sing-box 的节点列表
也重新纳入 r2s。

配置侧的求值、SOPS 键完整性、Xray 配置与隧道域名可以离线检查；设备真正上线后
还需要确认 `r2s.imdomestic.com` 已被 ddns-go 更新到当前 IPv6，并从 r5sjp 验证
`interconn-r2s` 已建连。若机器重装后 SSH host key 变过，必须先更新这里的 age
recipient，否则目标机无法解密新文件。

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

**下次重试的前提：**先在一台不当网关、也不吃 CGNAT 地址的机器上（比如 tank）
把 `auto_redirect=false` 时 TCP 不进 tun 的机制搞清楚，再回到 r6s。
不要再直接在网关上试——它一挂就是全家断网，而且 r6s 自己就是这台机器上网的
出口，回滚只能靠 tailscale 或者物理接触。

## 6. 隧道抽风的根因（2026-07-31 实测）

症状：浏览器开网页"秒死"，过一阵自己好。

### 结论：是 h610 单独那一条跨境链路差，不是整体

从 r5sjp 用 iperf3 打每个 portal（TCP 基线 + UDP 丢包）：

    portal      运营商    TCP 吞吐          UDP@30M 丢包
    shanghai    阿里云    220 / 211 Mbit/s  0.31%
    rpi4        移动      191 / 180 Mbit/s  0%
    r5s                   131 / 112 Mbit/s  6%
    r6s                    69 /  54 Mbit/s  4.8%
    h610        电信      4.82 / 3.64 Mbit/s  13%     <- 唯一的异类

**h610 比最好的慢 40 倍。** 而它的 RTT 是 89ms——在任何延迟检查里都健康，
这正是它能骗过所有按延迟选路的策略的原因。

> 早先这一节写的是「根因是 r5sjp 那条路的丢包」，依据是 r5sjp 上 5.5% 的累计
> TCP 重传率。那个结论**已被上面的对比推翻**：5.5% 是所有对端混在一起的数字，
> 而 h610 流量第二大、路最差，那个统计基本是它一家撑起来的。教训是聚合指标
> 不能用来给单条链路定罪。

### 用户可见的影响

从 h610 同时测直连和走隧道，各 160 次、间隔 2 秒：

    直连 www.baidu.com     失败   0/160  ( 0.0%)
    走隧道 1.1.1.1         失败  32/160  (20.0%)
    两者同时失败                0        <- 上行没问题
    只有隧道失败               32

失败成段出现（抓到 25 秒和 70 秒两个窗口）。20% 这个数字值得注意：dae 在五个
节点间分摊，**正好 1/5**——如果 h610 是唯一的坏路，数字完全对得上。这个假设
没有单独验证过。

### 已排除

h610 自身上行（直连 0/160 失败）、r5sjp 的 CPU/内存（load 0.00）、r5sjp 出网
（直连 60/60 全通）、网卡（errors/dropped 全 0）、检查目标本身、以及"流量压在
单个节点上"（实测五个 bridge 分布均匀，但注意那个计数里绝大部分是 dae 自己的
健康检查，不是用户流量，所以这条排除得不彻底）。

### UDP 在这条路上远好于 TCP

同一条 h610 链路：

    TCP        3.64 Mbit/s（10 秒内 431 次重传）
    UDP@10M    8.99 Mbit/s（9.2% 丢包）
    UDP@30M   25.8 Mbit/s（13% 丢包）

**UDP 送达是 TCP 的 7 倍。** TCP 把丢包当拥塞信号疯狂退避，而这里的丢包不是
拥塞造成的。这说明 hysteria2 那种带 FEC、拒绝退避的 UDP 传输在这条路上会有
数量级的改善。

**但 hysteria2 建不起来**：它是严格的 client→server，没有 xray `reverse` 那种
反向拨号，而 r5sjp 的 IPv4 在 NAT 后（10.1.2.107）、IPv6 入站被 linwhite 家的
路由器挡着（实测发 UDP 到它两个公网 v6 地址都收不到）。要用得先请他开一个
UDP 端口。开了之后 r5sjp 当 server、各 portal 当 client，反向隧道那套可以整个
拆掉。

### 结构性问题

**五个节点共用一个出口，冗余是假的。** 任何 r5sjp 侧或跨境段的整体问题都会让
五个同时失效，没有健康节点可切。选路策略再聪明也救不了这一类。

## 7. 选路：延迟指标看不见这个问题

h610 RTT 89ms、吞吐 4.8 Mbit/s、丢包 13%，而按延迟选路的策略认为它健康。
调研过的客户端里只有三个把质量纳入实时评分：

    vernesong/mihomo smart   延迟 + 丢包(TCP重传) + 吞吐
    Surge Smart Group        延迟 + 抖动 + 丢包（明确排除吞吐）
    Egern smart              延迟 + 抖动 + 成功率

upstream mihomo / sing-box / dae / Shadowrocket / Clash Verge / Karing /
Hiddify / NekoBox / Loon / v2rayA 全是纯延迟。dae 的五个策略
（random/fixed/min/min_avg10/min_moving_avg）没有任何丢包或带宽维度，
**指望调 dae 的 policy 解决这个问题是不可能的**。

上游 mihomo 明确不做：Clash Verge Rev 的 issue #7646 提了同样需求，维护者回复
「Mihomo Core 印象中没有直接提供测量带宽的 API…我对此 Issue 持否决态度」。

注意网上有博客声称 Hiddify「实时权衡丢包、RTT 和抖动」——**那是假的**，它的
`URLTestHistory` 结构体里只有 `Delay`，没有 loss 和 jitter 字段。

删节点不是解法：实测同一天内 rpi4 的延迟从 66ms 涨到 4.4 秒，而它的吞吐是
五条里最好的之一。链路质量随运营商、时段、v4/v6 大幅波动，要的是能感知质量的
选路，不是更短的节点列表。

## 8. r6s: dae -> mihomo(smart) 迁移记（2026-07-31 完成）

三次踩坑，都不是配置解析问题——**三次 `-t` 校验全过，服务全起不来或不通**：

1. **geodata。** mihomo 启动时找不到 GeoSite.dat 就联网下载，而这时 dae 已被
   替换掉、没有可用代理，下载卡死、全家断网。dae 模块本来就有
   `assets = [v2ray-geoip v2ray-domain-list-community]`，写 mihomo 模块时漏了。
   修法：`geo-auto-update: false` + ExecStartPre 把 store 里的 .dat 软链进
   `/var/lib/private/mihomo`（要带 `+` 以 root 跑，服务是 DynamicUser，
   普通 tmpfiles 在 StateDirectory 建好前就跑了）。
2. **DNS 根本没流经 mihomo。** `dns-hijack` 只劫持**进入 tun** 的流量，而本机查
   127.0.0.53 走回环、LAN 客户端查网关 IP 是本机目的地址，两者都不进 tun，
   于是查询直接落到 resolved 配的国内上游拿回投毒结果。dae 没这问题是因为它在
   eBPF 层连本机查询一起拦。修法：把 resolved 的上游指向 `127.0.0.1:1053`。
3. **换 DNS 模式后必须 `resolvectl flush-caches`。** 两次"还是坏的"都是缓存
   残留（旧的投毒记录 / 旧的 fake-ip），不是配置没生效。

### auto-redirect：mihomo 和 sing-box 的关键差异

sing-box 那次断网是因为 `auto_redirect` 把本机 TCP 重定向到 lo，源地址仍是
CGNAT 的 100.84.115.12，撞上 tailscale 的
`ip saddr 100.64.0.0/10 iifname != "tailscale0" drop`。

mihomo 用 metacubex/sing-tun v0.4.21，选项名一样，但那条 lo 重定向
（redirect_nftables.go:63 的 `nftablesCreateRedirect`）被 `if AutoRedirectMarkMode`
包着，而 mihomo **只在用了 `route-address-set` / `route-exclude-address-set`
（rule-set 形式）时才开 mark mode**（listener/sing_tun/server.go:468），
sing-box 1.13 则是在 Linux 上无条件开启。

所以：用普通的 `route-exclude-address` 前缀列表排除 tailscale 段是安全的，
**绝不要**换成 `-set` 形式。已实测确认本机 IPv4 正常。

### 为什么用 redir-host 而不是 fake-ip

三个诉求指向同一个选择：

- **mihomo 停掉后还能上网**：fake-ip 的 198.18.x.x 被 resolved 缓存后，
  mihomo 一停全成死地址，连国内站点也不通。
- **不留指纹**：198.18.0.0/15 是 RFC 2544 保留段，正常网络里不该出现。
- **LAN 设备自己开代理不打架**：tun 的 dns-hijack 会截下 LAN 里某台机器自己的
  clash 发给 223.5.5.5 的查询。fake-ip 下它拿回 r6s 的假 IP 当成"真实 IP"，
  要是它也用默认的 198.18.0.0/15，它的 tun 还会把这些当成自己的假 IP 反查，
  查出毫不相干的域名。

代价（机制决定，配置绕不过）：IP->域名 的还原表是 4096 条 LRU
（dns/enhancer.go:188），淘汰后退化成按 IP 匹配；CDN 上几十个域名共用一个 IP
时 last-writer-wins，反查可能串。fake-ip 每域名一个独占假 IP 没这两个问题。

redir-host 必须把域名解析对（拿到毒 IP 就会去连毒 IP），所以配套的分流 DNS
不是可选项。一比一照搬 dae：

    dae qname(geosite:cn,...) -> alidns          ->  nameserver-policy
    dae fallback: alidns                          ->  nameserver
    dae response{ip(geoip:private)&&!qname(cn)}   ->  fallback + fallback-filter
    dae 国外 DNS 经代理                            ->  respect-rules: true

`respect-rules` 开了之后 `proxy-server-nameserver` 必须非空否则启动报错
（config.go:1426）——这个约束正好防住"要连代理得先问代理"的死循环。

### 迁移后实测

    google.com    200  0.86s     解析 142.251.23.113（真实，之前是投毒的 157.240.7.20）
    youtube.com   200  2.42s     AAAA 2404:6800:...（真实，之前是 2001::1）
    github.com    200  0.84s
    baidu.com     200  0.05s     直连

走代理失败率 4/160 (2.5%)。**但这不能和之前的 20% 直接比**——那是在 h610 上用
dae 测的，主机和软件两个变量都变了。要干净归因得在同一台上做 dae/mihomo 对比。

## 9. h610 试 mihomo 失败并回滚（2026-07-31）

r6s 迁移成功之后把 h610 也切过去，**cliproxy 随即不可用**，回滚到 dae。
r6s 保持 mihomo 不变。

症状：`POST /v1/chat/completions` 先是 500（超时 1m21s），随后大量 3ms 的 503。
cliproxy 报的是

    Post "https://chatgpt.com/backend-api/codex/responses": EOF

### 排除掉的（下次不用重查）

- **不是 DNS。** 一开始确实是 DNS：chatgpt.com 被解析到 `157.240.8.50` 和
  `2a03:2880:...face:b00c:...`（Facebook 的段，典型投毒）。根因是 fallback 用了
  DoT（`tls://8.8.8.8:853`）经代理出去，而这条链路丢包 13%，TLS 握手那次多余的
  往返经常超时，fallback 一失败就退回国内 DNS 的投毒结果。改成 `tcp://` 之后
  解析恢复正常（真实 Cloudflare 地址），**但 EOF 依旧**。
- **不是路由。** mihomo 日志明确记录
  `cli-proxy-api → chatgpt.com:443 match Match using im[...]`，流量确实经代理。
- **不是容器网络。** 容器 `--network=host` 出网正常，cliproxy 自己刷新 GitHub 上
  的模型目录成功。
- **不是凭据。** `1 clients (1 auth entries)` 正常加载。
- **不是节点。** 一度以为是：钉到 sh 成功、钉到 rpi4/h610 失败。但十分钟后同样
  钉 sh 也失败了 —— **那次成功是偶然，单次采样不足以下结论**。

### 没定论的

EOF 只发生在 `POST /backend-api/codex/responses` 这个长请求上，普通 GET 正常
（403 是 Cloudflare 对裸 curl 的正常防护响应）。dae 时代这个请求也要 6~16 秒
才回来，本来就在超时边缘。**怀疑**是 mihomo 与 dae 在长连接超时/缓冲行为上的
差异把它推过了线，但没有证据。

### 两个让调试变难的因素

- **cliproxy 的冷却机制**：一次失败后接下来几分钟全返回
  `auth_unavailable`，任何间歇性失败都被放大成持续不可用，每轮只有第一发是
  有效样本。
- **smart 组在节点间轮转**（实测 10 分钟内 sh 3 次 / rpi4 2 次 / r5s 1 次 /
  r6s 1 次），不收敛到最优。对普通浏览无所谓，对"一次失败就冷却"的服务是致命的。

### 下次怎么查

**别再拿 h610 当试验场** —— 它远程、无人、跑着 airport/matrix/livekit/headscale
一堆服务，不适合迭代式调试。正确做法是在 r6s 上部署一份 cliproxy，或者用 curl
构造等价的长 POST 反复打，在 dae 和 mihomo 之间做真正的 A/B（每次测之前重启
cliproxy 清冷却，或者直接绕开 cliproxy 用 curl）。

`nixos/hosts/h610/system.nix` 里 `my.mihomo.*` 那几行是注释掉的现成配置，
重新试的时候连同 import 一起放开即可。

---

## 10. mihomo 每隔几小时崩一次（2026-08-01，已修）

症状是「r6s 上 mihomo 过一段时间就退出」。7-31 20:27 部署，8-1 06:25 和 10:18
各崩一次，两次都是人发现断网手动重启才恢复的。

不是 OOM 也不是被 kill，是 panic：

```
panic: should never be called
main.main.func1                      main.go:87
net.(*Resolver).dial                 net/lookup.go:696
```

`main()` 给 `net.DefaultResolver.Dial` 装了个守卫，任何走 Go 标准库解析器的调用
都会打印全部 goroutine 栈然后 `os.Exit(2)`——mihomo 的 DNS 必须走它自己的解析
器，走到标准库就说明有 bug。触发它的链是 smart 组的「异常状态码检测」：

```
Smart.recordConnectionStats   smart.go:1536
→ Smart.checkNodeQuality      smart.go:1686
→ Smart.StatusTest            smart.go:1783
→ Proxy.StatusTest            adapter.go:399   client.Do()
```

某条走代理的 443 连接下行不足 0.03MB 时，它会拿这条连接的 Host 现场发一个
`https://<host>/?z=<random>` 探测。探测用的 `http.Client` 允许跟 3 次跳转，而它的
Transport **只设了 `DialTLSContext`，没设 `DialContext`**。一旦某次跳转落到明文
`http://` 上，net/http 就走 `DialContext`——nil——退回 Go 的零值 Dialer 和标准库
解析器，撞守卫。

坐实这一步的是崩溃现场的 goroutine 124318：`Transport.dialConn` 的 `targetScheme`
长度是 4（`"http"`，不是 5 的 `"https"`），`targetAddr` 10 字节 = 7 字符主机 +
`:80`。而整个函数里唯一的请求是从 `"https://"` 拼出来的，只能是跳转过来的。

**教训：要同时满足「走代理」「443」「下行 < 0.03MB」「跳转到 http://」才会中。**
这类依赖具体流量的崩溃，配置校验（`mihomo -t`、`just check-*`）一个都测不出来，
只能靠读崩溃栈。别看到「服务退出」就先怀疑 OOM/看门狗——`journalctl | grep panic`
是第一步。

`StatusTest` 是 vernesong fork 独有的，上游 MetaCubeX 没有这个函数；fork 里最后
一次改 `adapter/adapter.go` 是 2026-07-24，早于我们钉的 commit，所以上游没修。
补丁在 `pkgs/mihomo-smart/statustest-dialcontext.patch`，让跳转那一跳也走代理。
**下次 bump `rev` 时要确认这个补丁还需不需要**（上游修了就删掉）。

同时补上了 `Restart=always` / `RestartSec=5s` / `startLimitIntervalSec=0`。nixpkgs
的 mihomo 单元默认 `Restart=no`，崩了就一直躺着；router 模式下 resolved 指向
`127.0.0.1:1053`，mihomo 没了 DNS 全瞎，等于整个局域网断网。**真正的痛点不是崩，
是崩了不回来**——关掉次数限制是故意的，对一台没人在旁边的路由器，「一直重试」
严格优于「试几次就放弃然后永久断网」。

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
