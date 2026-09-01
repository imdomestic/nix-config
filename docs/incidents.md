# 事故与排查记录

代码里放"这行为什么这么写",这里放"那次到底怎么回事"。

判据:如果一段注释回答的问题不是「读者盯着这行时会冒出来的」,它就该在这里。
典型的是根因调查过程、当时的实测数据、试过但走不通的路。代码里只留一行指针。

按时间倒序。每条给一个锚点,代码里用 `docs/incidents.md#<锚点>` 引用。

---

## 2026-09-01 · 悉尼→日本:打洞比中转慢一倍,但带宽是中转的三倍 {#syd-jp-relay-beats-direct}

起因是一个看着不合理的现象:同在悉尼那条上行后面,**Mac ping r5sjp 130ms,
rpi4 稳定 276ms**。同一条线、同一个目标,差一倍。

原因不在机器,在**隧道走法**。tailscale 给两台选了不同的路:

| | Mac(m1elite) | rpi4 |
|---|---|---|
| 路径 | relay `tok`(东京 DERP) | direct `219.104.128.80:4632` |
| RTT | 110–132 ms | 276.05 / **276.21** / 276.39 ms(mdev **0.113**) |

rpi4 那个 mdev 0.113ms 是关键信号:**抖动几乎为零 —— 不是拥塞、不是丢包,
是路由绕远**。mtr 打 UDP 4632 过去:

```
 2. 27.122.122.169   1.1ms   bdr01-ipt-47bourke-syd.au.as38195.net   ← Superloop,悉尼
 3. 172.21.68.229  148.2ms   ← 一跳之内 +147ms,太平洋已经过去了
 7. 89.149.184.237 168.1ms   ae0.cr10-lax2.ip4.gtt.net               ← GTT,洛杉矶
 9. 203.181.106.x  147.0ms   ← IIJ,日本
10-12. 106.187/27.85/27.86/106.139  250–280ms  ← NTT 消费线最后一段
```

**悉尼 → 洛杉矶 → 东京,横穿太平洋两次。** 而 tailscale 自己的 netcheck 给出
的真实悉尼→东京是 **105ms**(rpi4 上 `tok: 100.4ms`)。276 − 105 ≈ 170ms
全是绕路的代价。r5sjp 挂在 NTT 消费线上,它的上游选了 GTT,这一段我们改不了。

Mac 之所以快,是因为它**打洞失败了** —— `tailscale ping 100.64.0.16` 从 Mac
上全部超时(它在 rpi4 NAT + hotspot NAT 后面,三层 NAT),于是老实退回东京
DERP。rpi4 只隔一层 NAT,打洞成功,然后被那条烂路坑了 146ms。

### 两条路的完整对照

同一台 rpi4、同一个 r5sjp,靠临时 nft 规则丢掉去往 `219.104.128.80:4632` 的
UDP 来切换(约 10 秒回落),iperf3 各跑 10 秒:

| | 打洞 direct | 中转 DERP `tok` |
|---|---|---|
| RTT | 276.3 ms | **111.4 ms** |
| 上行 单流 | **62.1** Mbps | 21.5 Mbps |
| 下行 单流 | **76.1** Mbps | 21.8 Mbps |
| 上行 8 流 | 53.5 Mbps,重传 **14905** | 22.1 Mbps,重传 5 |
| 下行 8 流 | **82.9** Mbps,重传 **15797** | 22.1 Mbps,重传 3 |

三个读数值得单独记:

1. **DERP 是被限速的,不是被拥塞的。** 单流 21.5、八流 22.1,一模一样,而重传
   只有个位数。零重传 + 加流不涨 = 令牌桶。这 22 Mbps 是硬顶。
2. **直连的瓶颈是那条 100M 上行,不是 276ms 的 RTT。** 单流就能跑到 62–76
   Mbps —— 原本担心的 LFN/窗口问题不存在。
3. **直连上多开流是净损害。** 上行八流从 62 掉到 53.5,代价一万五千次重传。
   和 [#syd-hotspot-no-multilink](#syd-hotspot-no-multilink) 是同一个教训:
   这条线上「并发叠加」永远不成立,瓶颈在最后一公里。

结论是没有哪条全面更优:传文件用直连(带宽 3.5×),交互用中转(延迟 2.5×)。
所以做成了手动开关 `ts-relay on|off|status`(`nixos/modules/ts-relay`),
而不是选一个固定下来。

### 被我带偏的地方

**一、拿两台机器对比,以为在比机器。** 最初的问题是「Mac 和 rpi4 为什么差一
倍」,很容易顺着往「rpi4 的网络栈/CPU/MTU」上找。实际两台的差别只有一个:
tailscale 给它们选的路不同。**要比路径就必须在同一台机器上切换路径**,否则
永远分不清是机器差异还是路径差异。

**二、`ping` 到公网 IP 全丢包,差点以为链路不通。** r5sjp 那个 IP 和东京 DERP
都不回 ICMP。真实路径得用 mtr 打**实际在用的那个 UDP 端口**(`-u -P 4632`)
才看得见,ICMP 探测在这里完全没有参考价值。

**三、把 `-P 8` 当成"测上限"的标准手法。** 在这条链路上它测出来的是更低的数字
加一万多次重传。多流只在单流受窗口限制时才有意义,而这里不是。

---

## 2026-08-31 · 悉尼公寓的 hotspot 能多拨,但带宽叠不起来 {#syd-hotspot-no-multilink}

想法是国内宽带那套「多拨」:hotspot 按 MAC 认证(`check-login.html` 里
`username` 就是 MAC),那在 rpi4 上开几个 macvlan 造多个 MAC,各自认证一遍,
是不是就能叠出几份 100Mbps。运营商也说"最多支持 5 个同时在线"。

**技术上完全可行,但带宽不叠。** macvlan 那条链路每一步都成功了 ——
独立 DHCP 地址、独立过 portal:

```
"ip":"172.24.206.114"
"mac":"02:11:22:33:44:01"
"loggedIn":"yes"
```

可一压并发就对半分。最终那组干净数据(两台真实设备、不同物理介质、
非 Cloudflare 源):

| 场景 | 速率 |
|---|---|
| Mac(wifi) 单独 | 13.23 MB/s |
| rpi4(有线) 单独 | 13.09 MB/s |
| 并发 Mac | 6.51 |
| 并发 rpi4 | 7.47 |
| **并发合计** | **13.98 MB/s** |

合计等于单线。**限速挂在账号或公寓出口那一层,不在 station 也不在链路层**,
所以 5 个 session 只是把同一个 100Mbps 切碎,还白占 4 个设备名额。
"5 个同时在线"是设备并发数,不是带宽通道数。

**踩过三个坑,每个都足以得出相反结论:**

- **第一版实验用 macvlan,分辨不出限速在哪一层。** 所有 macvlan 都从同一个
  物理端口出去,所以"对半分"既可能是账号级限速,也可能是端口/station 级 ——
  这两种的后续方案完全不同(后者意味着换成 wlan0 + 有线双物理链路就能叠)。
  必须拿**两台真实设备、不同介质**重测才能区分。结论是账号级。
- **Cloudflare 测到一半开始返 429,那批数据全是假的。** speed.cloudflare.com
  被我们打太多次之后,`speed_download` 掉到 11 B/s 一路"极慢",看着特别像
  "限速狠"。实际 `http_code` 是 429。另外它对 `bytes=104857600` 直接 403,
  上限在 50MB。**测速脚本一定要把 http_code 一起打出来**,只看速度会被骗。
  换 AARNet(`mirror.aarnet.edu.au`,澳洲学术网)之后数据才稳定。
- **所有设备共享 NAT 后的同一个公网 IP**,所以"同一目标对源 IP 限流"是真实
  风险,不能拿单一 CDN 的并发结果下结论。

hank 最初观察到手机和 Mac 同时测能明显破 100Mbps,复测后确认是看错(多半是
两次测速没重叠,各自峰值相加)。**这个观察一度是唯一指向"能叠"的证据**,
差点让人去做 wlan0 双链路那套 —— 值得记住的是它被推翻只用了一次同步复测。

所以 rpi4 保持单线,配置里没有任何多拨/负载均衡的东西。要更快只能动套餐
(portal 前端有 change-plan / purchase,走 eWAY)。

## 2026-08-31 · 悉尼到国内绕欧洲,而且是晚高峰才绕 {#syd-cn-route-via-europe}

rpi4 落到悉尼公寓之后,到国内 451ms。`nexttrace sh.imdomestic.com` 的形状:

```
2  27.122.122.169  Superloop 悉尼本地           0.91 ms
3  172.21.68.229   RFC1918 + MPLS             286.10 ms   ← 一跳 +285ms
...  (9 跳 MPLS 私有地址,全部 285ms 上下,纹丝不动)
12 212.222.6.54    GTT  法国马赛              286.65 ms
13 213.200.117.178 GTT  荷兰阿姆斯特丹        292.30 ms
14 81.173.18.1     ChinaTelecom 阿姆斯特丹    293.86 ms
16 202.97.83.145   ChinaTelecom 上海          404.57 ms
26 101.132.183.117 阿里云上海                 451.90 ms
```

**判据是 hop2 → hop3 那一跳:0.91ms 变 286.10ms,而之后九跳全部停在 285ms
不动。** 那 285ms 不是某一跳慢,是整条跨洋链路的 RTT —— 到 hop 3 时人已经在
欧洲了,后面那串 RFC1918 是 Superloop 的 MPLS 内网。所以这是
悉尼 → 马赛 → 阿姆斯特丹 → 上海,绕了大半个地球,太平洋方向那条 ~130ms
的路压根没走。

**是时段性的,不是固定路由。** hank 白天测到日本约 120ms,当晚(悉尼傍晚)
`tailscale ping r5sjp` 是 257ms —— 而且那是 direct(`219.104.128.80`),
不是 relay 绕的。同一条链路白天正常、高峰绕欧洲,像是 Superloop 在高峰
把出国流量甩给 GTT transit。

**别拿 anycast 目标当"到国内"的样本。** `ping 223.5.5.5` 只有 191ms,
`ping 1.1.1.1 / 8.8.8.8 / www.google.com` 更是 0.7ms —— 前者阿里 DNS 有
海外节点,后者是公寓网络里就有 Google Global Cache。这些数字全都不反映
到中国大陆真实服务器的路径,只有 451ms 那个才是。第一次量的时候差点被
0.7ms 骗过去,以为"这网络哪都快"。

这条路 rpi4 改不了,是上游的 transit 选择。真正能做的是别让本地配置雪上
加霜 —— 见 docs/decisions.md#rpi4-drop-dae。

## 2026-08-31 · rpi4 搬到悉尼公寓 —— 挖出 captive portal 的登录表单 {#rpi4-sydney-captive-portal}

rpi4 从国内的 PPPoE 网关变成悉尼公寓里的旁路路由,上游是 Vostro/Superloop 的
`iglu` 网络,先认证才给网。要让一台没人值守的机器自己登进去,得先知道表单长什么样。

**portal 的地址不用猜,DHCP 就给了。** `ipconfig getpacket`(macOS)/networkd 的
租约里有 option 114 `captive_portal_url = https://iglu.authentication.technology/api`,
这是 RFC 8908。那个 `/api` 端点返回 `{"captive":false,"seconds-remaining":86191}`,
可以直接当"还剩多久掉线"用。

**登录是两段,而只有第二段真的放行网络。** 前端是个 Gatsby SPA(`iglu.vostro.live`),
第一段 `POST https://iglu-api.vostro.app/rest.api/login` 收 JSON `{userName,password}`,
返回 JWT —— 那是给 portal 自己(改套餐、管设备)用的。真正让网关放行的是第二段:
SPA 里一个隐藏的 `<form method="post">` 提交到网关,

```
POST https://iglu.authentication.technology/login
Content-Type: application/x-www-form-urlencoded
radius11=hotspot&username=<user>&password=<pass>
```

`radius11=hotspot` 是写死的隐藏字段。网关是 MikroTik hotspot —— 认出来是因为
`/check-login.html` 的返回里有 `link-login`、`interface-name`,还有一个没被替换的
模板变量 `"uptime-sec": "$(uptime-sec)"`。状态判据就用这个端点的 `.loggedIn == "yes"`。

**怎么挖出来的:source map 是开着的。** `iglu.vostro.live` 上每个 chunk 都能取到
同名 `.js.map`,`sourcesContent` 里是完整的 React 源码,`src/controls/login.jsx`
一眼就看到那个隐藏 form。不用逆混淆代码,也不用真的登录一次去抓包。

**踩过的两个坑:**

- **在已认证的机器上测不出成功/失败。** 拿假用户名 POST 过去,返回的也是 302 到
  SPA 首页,和成功一模一样;已登录的客户端网关根本不做认证。想验证只能先登出,
  代价是真的断网,所以判据只能靠事后查 `/check-login.html`。
- **用户名不是邮箱。** 邮箱能过第一段(REST API 支持按 email 查),但第二段是把
  表单原样丢给 RADIUS 的。账号真实的 `userName` 是一串数字(portal 的
  `getCurrentUser` 里能看到)。当时在已认证的机器上分辨不出哪个能用,所以脚本
  写成按候选列表依次试;**实测结果是数字 userName 过,列表已收敛成它一个**。
  候选循环的机制留着 —— 换一处网络时它还是那个"先试哪个"的问题。

**部署时踩的:`writeShellApplication` 的 runtimeInputs 就是全部 PATH。** 第一版
漏了 gawk,服务起来直接 `awk: command not found` —— systemd 给的 PATH 里没有它,
不像交互 shell 那样有 `/run/current-system/sw/bin` 兜着。取网关那一步因此改成
`ip -j` 出 JSON 交给 jq(反正要用 jq 读 check-login),顺带把 `sleep` 依赖的
coreutils 也显式列上。同一类错误还有一个在后面等着:脚本在 awk 那行就 errexit
退出了,`sleep` 那处根本没走到。

**为什么脚本用 `curl --resolve` 而不是靠 DNS:** `iglu.authentication.technology`
的 A 记录指向 `172.24.0.1`,也就是默认网关自己(公共 DNS 也这么返回)。认证之前
walled garden 只放行到网关,dae 配的那些上游(alidns / dns.google)一个都解析不出来。
`--resolve` 把域名钉到网关地址,同时保留 SNI 和证书校验,不用降级成 `--insecure`。

顺带:portal 的设备是登录时自动注册的(`deviceLimit: 100`,已经躺着 4 个 MAC),
所以 rpi4 不需要事先去 portal 里登记 MAC。

## 2026-08-31 · tmux-agent-sidebar 的状态图标挤成一团 —— ghostty 回退到中文字体 {#ghostty-ambiguous-width-fallback}

**症状:** 刚装上 tmux-agent-sidebar,顶部那排过滤器 `≡1 ●2 ◎0 ◐1 ○1 ✕0` 里,
圆圈后面的计数数字看不见,几个图标糊在一起。而第一个 `≡1` 显示完全正常。

**根因是字体回退,不是插件。** 图标定义在插件的 `src/ui/icons.rs`,七个默认字形
逐个查 `RecMonoSmCasualNerdFontMono-Regular.ttf` 的 cmap:

| 码位 | 字符 | 用途 | 字体里有没有 |
|---|---|---|---|
| U+2261 | `≡` | all | 有 |
| U+25CF | `●` | running | **缺** |
| U+25CE | `◎` | background | **缺** |
| U+25D0 | `◐` | waiting | **缺** |
| U+25CB | `○` | idle | **缺** |
| U+2715 | `✕` | error | **缺** |
| U+00B7 | `·` | unknown | 有 |

缺的五个正好就是显示错乱的五个。这五个都是 UAX #11 里的 **East Asian
Ambiguous** 宽度字符:插件用 Rust 的 `unicode-width` 算宽度,非 CJK 模式下一律
返回 1;而字体里没有,ghostty 顺着 `font-family` 的下一项回退到 PingFang SC ——
中文字体把这些几何符号按全角设计,画出来占两格。程序按一格排版、字体按两格画,
后面那一列就被盖掉了。

**误导我的是原来那条注释。** 它写的是「Recursive 没有 CJK 字形,不给 fallback
的话 ghostty 会挑到宋体楷体」—— 于是我一开始只往「中文显示」的方向找,还去数了
`~/Library/Fonts` 里的 SimSun/SimHei,怀疑是它们被 cascade 选中。实际问题是
**非 CJK 的符号也会掉进这条回退链**,而链上第二级(也是最后一级)偏偏是中文字体。
两级回退、且末级是 CJK 字体,这个组合本身就是坑。

**修法:** 在中间插一层拉丁等宽字体。Menlo 是 macOS 自带的,查过 cmap,那五个
字形全有、都是半角;它完全没有 CJK 字形,所以中文照样落到 PingFang SC,顺序不会
被抢。

绕过去的办法也有:插件自己暴露了 `@sidebar_icon_*`,可以换成 Nerd Font 的 PUA
图标(U+F0C9 / F111 / F192 / F042 / F10C / F00D,`NerdFontMono` 变体的字形本来
就被压进单格)。但那只治这一个插件,下一个用几何符号的 TUI 还会再撞一次,所以
最后改的是字体链。

---

## 2026-08-19 · 未提交的 flake.lock 让 h610 上三次 max 部署被静默回滚 {#max-uncommitted-lock-rollback}

**症状:** 14:50 部署完 max 的镜像功能,验证通过 —— QQ 群消息扇出到 iMessage,
`relay:108806:28` 落库。三分钟后同样的操作不再产生 relay 行,`message_deliveries`
只剩 `source:` 一条。数据库里 endpoint 28 从 `mirror` 变回了 `standalone`。

**根因:** 14:52:59 有人从**已提交的树**跑了一次 rebuild。当时 `flake.lock` 里
max 的 bump 只在工作区,没提交:

```
committed flake.lock max rev: 7ef8ee35   ← 当天所有工作之前
工作区 flake.lock max rev:   bb64147
```

于是 gen 338 把当天三次部署一起换掉了:

```
gen 336  14:32:20  max=nh8qv2ym   iMessage @ 修复
gen 337  14:50:33  max=3g7mrkdf   镜像
gen 338  14:52:59  max=m3xf7ssv   ← 从 committed tree 构建,退回 7ef8ee35
```

直接 grep 两个 build 的源码快照,不用猜:

```
gen 337 的 source: mirrorQQGroup 8 次
gen 338 的 source: mirrorQQGroup 0 次,anchorSelf 也 0 次   ← 连 @ 修复都没有
```

**回滚不是"少了个功能",它会改数据。** 旧 max 的 `iMessageWorker` 里
`EndpointStandalone` 和 `Nothing` 是写死的,启动时执行

```sql
UPDATE conversation_endpoints SET endpoint_mode = 'standalone' ... WHERE endpoint_id = ?
```

把 endpoint 28 降了级。max 那边配置是权威、每次开机覆盖 DB,所以**把二进制换旧等于
让它按旧配置重写状态**。这类设计下,回滚一个版本和回滚一次数据迁移是同一件事。

**误导我的地方:** 我先去查镜像的代码和扇出 SQL 了。14:50 拓扑对、14:53 拓扑错,
中间只隔三分钟,第一反应是条件写错或者配置没生效。真正的线索是日志里少了一个字段:

```
14:50:37 iMessage worker started  endpoint_id=28 mode=mirror native_replies=true
14:53:03 iMessage worker started  endpoint_id=28 native_replies=true      ← 没有 mode
```

`mode` 是当天新加的字段。**它不是值变了,是根本没打印** —— 说明换掉的是二进制,不是
数据。两行并排看才反应过来。教训:排查"刚才还好现在不好"时,先确认跑的还是不是同一个
东西,再去看它的行为。

**AGENTS.md 早就写了这条。**「After a rebuild: commit and push promptly」下面第一句就是
"A machine running code that is not on the remote is unreproducible. The next deploy
from a clean checkout silently reverts it, and nobody sees a conflict — the change just
disappears."我跳过了 rebuild 前的 freshness check,而那一步正是会发现 flake.lock
未提交的地方。

**修复:** 回到 gen 337 激活 —— endpoint 28 自愈成 mirror,因为新二进制读得到
`mirror_qq_group`,不用手改数据。然后提交推送 `flake.lock` 与 `system.nix`。验证是从
**已提交的干净树**重新构建,和正在跑的系统同一个 store path:

```
built:   /nix/store/pl7r7p25...-nixos-system-h610
running: /nix/store/pl7r7p25...-nixos-system-h610
```

## 2026-08-17 · h610 冷启动后 headscale 对外失联 13 小时 —— nginx 和 tailscaled 互等 {#nginx-tailnet-bind-deadlock}

**症状:** h610 在 10:45 硬崩(日志戛然而止,没有任何 shutdown 序列),22:38 重新
开机之后,tailnet 一直没有恢复。人还能从公网 ssh 进去,`systemctl status
headscale` 是 active、进程在跑、日志在刷 —— 但外面所有节点都连不上。

**headscale 本身从头到尾没出过问题。** 它监听 `127.0.0.1:8080`,一直好好的;
headplane-agent 能连上是因为走 loopback。真正挂掉的是它前面的 nginx:

```
× nginx.service - failed (Result: start-limit-hit) since 22:39:04
  nginx-pre-start: bind() to 100.64.0.3:80 failed (99: Cannot assign requested address)
```

**根因是一个自锁的环:**

```
nginx 起不来
   └─ 要 bind 100.64.0.3:80          (kennethbot 那个 tailnet-only 的 server 块)
        └─ 这个地址由 tailscaled 分配
             └─ tailscaled 登录不上
                  └─ 要连 https://tailscale.imdomestic.com:8443/key
                       └─ 解析到 114.225.151.40:8443 = h610 自己的公网口
                            └─ connection refused ← 因为 nginx 没起来
```

三个证据同时成立才敢下这个结论:

| 探针 | 结果 |
|---|---|
| `ip -brief addr show tailscale0` | 只有 `fe80::/64`,**没有 IPv4** |
| `tailscale status` | `You are logged out. fetch control key: … connect: connection refused` |
| `ss -lntp \| grep 8443` | 空 —— 没有任何监听者 |

**为什么不自愈:** `Restart=always` 看着像会一直重试,但 `StartLimitBurst=5`
在 51 秒内(22:38:13 → 22:39:04)就被耗尽,systemd 从此拒绝再启动它。
`Restart=always` 和"永远会重试"不是一回事。

**为什么以前没事:** 这个环一直都在。热重启时 tailscaled 常常能从状态文件里
快速恢复地址,赶在那 5 次重试窗口内;这次冷启动 + 前面 12 小时宕机,赶不上了。
**能自愈的竞态和不能自愈的死锁,区别只在于运气。**

**救火:**

```bash
sysctl -w net.ipv4.ip_nonlocal_bind=1
systemctl reset-failed nginx.service && systemctl start nginx.service
```

`reset-failed` 不能省 —— 不清掉 start-limit 计数,`start` 会被 systemd 直接
拒绝,而且不给任何解释。

**永久修法:** `boot.kernel.sysctl."net.ipv4.ip_nonlocal_bind" = 1`(允许绑定
尚不存在的地址,从根上打断环)+ `systemd.services.nginx.startLimitIntervalSec = 0`
(别再永久放弃,后者防的是别的晚到资源,比如 ACME 证书)。两条都在
`nixos/hosts/h610/system.nix`。

**最值得记的一条:一个只服务内网的 server 块,可以把整台机器的对外服务全部
带走。** nginx 的 config test 是全有或全无 —— `kennethbot.inner.imdomestic.com`
这个只给 tailnet 用的面板绑不上地址,连带 8443 上的 headscale 和订阅端点一起
起不来。凡是 listen 到"要等别的服务才存在"的地址上,都有这个性质。

---

## 2026-08-16 · tailnet 上的 web 面板在浏览器里全是 502,curl 却全绿 {#tailnet-panels-502}

**症状:** 刚部署好的 headplane,浏览器开 `http://100.64.0.3:3001/admin` 返回
502。服务本身没问题 —— h610 上 `systemctl is-active headplane` 是 active、
`ss -ltn` 看得到 `100.64.0.3:3001`,从 h610 本地和从 mac 上 curl 都拿到 302。

**这不是 headplane 的问题,而且不只 headplane。** 走代理时整个 tailnet 的面板
都是 502:

```
http://100.64.0.3:3000/    (Grafana)      502
http://100.64.0.5:9090/ui  (metacubexd)   502
http://100.64.0.3:9009/    (Prometheus)   502
```

**根因是 mac 上的 Clash Verge。** 三种写法的结果不一样,而差别正好指出机制:

| 写法 | 直连 | 经 `-x 127.0.0.1:7897` |
|---|---|---|
| `http://h610:3001/admin`(MagicDNS 短名) | 302 | **302** |
| `http://h610.inner.imdomestic.com:3001/admin` | 302 | 502 |
| `http://100.64.0.3:3001/admin` | 302 | 502 |

- **裸 IP:** Verge 的系统代理 bypass 用的是它的默认表(`use_default_bypass:
  true` + `system_proxy_bypass: null`),里面有 `127.0.0.1` / `192.168/16` /
  `10/8` / `172.16/12`,**唯独没有 `100.64.0.0/10`**。浏览器于是把 tailnet
  地址交给了 mihomo。规则文件里其实有 `IP-CIDR,100.64.0.0/10,DIRECT,no-resolve`
  (主配置第 153 行),但当前 profile 挂着 `script` 扩展 —— **live 配置和文件里
  读到的不是一回事**,照样 502。
- **FQDN:** 命中 `DOMAIN-SUFFIX,imdomestic.com,DIRECT`,可 DIRECT 要 mihomo
  自己解析,而它那套 DNS 不认 `100.100.100.100`;TUN 模式又劫持了 DNS,
  `dig h610.inner.imdomestic.com @1.1.1.1` 返回 `198.18.0.4` —— fake-ip 段,
  连不出去。
- **短名能过**是因为它走系统 resolver + 搜索域 `inner.imdomestic.com`,直接落到
  `100.100.100.100`。

**修法:** 面板地址一律用 MagicDNS 短名(`http://h610:3001/admin`)。想让裸 IP
也能用,得在 Clash Verge 的系统代理 bypass 里加 `100.64.0.0/10` —— 那是 GUI
应用自己的配置,不归这个仓库管。

**最值得记的一条:`curl` 验证不出这个问题。** curl 不读 macOS 系统代理设置
(只认 `http_proxy` 环境变量,那台没设),所以它天然绕过 Verge,三种写法全是
302。要复现浏览器那条路必须显式 `curl -x http://127.0.0.1:7897 ...`。这和
[#dae-breaks-lego-dns01](#dae-breaks-lego-dns01) 那次正好反过来 —— 当时是 curl
成功而 openssl 失败,这次是 curl 全绿而浏览器全挂。**判定一个服务"没问题"之前,
先确认你的探针和真实使用者走的是同一条路。**

---

## 2026-08-15 · 加了一台机器,`nix flake check` 就撑爆 runner {#deploy-schema-timeout}

**症状:** `flake-check` 工作流里的 `nix flake check` job,卡在

```
checking derivation checks.x86_64-linux.deploy-schema...
```

十几分钟不动,然后 `exit code 143`(SIGTERM)。日志里没有 OOM、没有磁盘告警,
所有 NixOS 配置在这之前都已经检查通过。

**触发点:** 最后一次绿是 2026-08-14 11:31,之后进来的第一批就是
`4a90b29 added h310` 那几个 commit。h310 进了 deploy 节点,还带 4 个 home:

```
deploy 节点数 9,profile 总数 35
h310: [home-fendada, home-hank, home-kenneth, home-linwhite, system]
```

**机制:** `checks` 原本是 `deployLib.deployChecks self.deploy` —— 吃的是**整个**
deploy,于是 `nix flake check` 在一个进程里深度展开 9 个节点、35 个 profile
(其中约 26 个是 home)。注意用的是 `--no-build`,所以卡的是**求值**不是构建。
再加一台带 4 个 home 的机器就越过了 runner 的资源线。

**排查时踩的坑(值得记):** 一开始怀疑是同一天开的 `nix.gc` 改了所有 host 的
closure、导致缓存全失效。**这个猜测是错的** —— 翻我第一个 commit 之前的三次
run,签名完全一样(14m32s / 12m57s / 12m24s,全部卡在 deploy-schema、全部 143)。
比对「最后一次绿之后进来了什么」比对着现象猜快得多。

**修法:** 拆成每台一个,并从 `checks` 挪到非标准输出 `deployChecks`:

- `nix flake check` 不再碰它(只会说一句 "unknown flake output",已在 ci.yml 的
  警告白名单里)。本地实测从「跑不完」变成 **21.5 秒**。
- 真正的验证挪进矩阵 job:那边每台**本来就**求值过自己的 toplevel,顺手验自己
  这一个节点几乎不要钱。而且从「一个大 check」变成「每台一个」,哪台坏了一眼
  看得出来。
- 顺带补上一个真实缺口:矩阵原本只验 system 不验 home
  (`just switch` 也是 system only),现在每台会一并求值自己的 home profile。

矩阵覆盖的机器比 deploy 节点多(笔记本、WSL、没有 tsIp 的那些),CI 里用
`nix eval` 探一下 attr 存不存在来跳过,而不是再维护一份主机名单 —— 那种名单
一定会和 `mkDeployNodes` 的判据漂移。

---

## 2026-08-15 · CI 连红 8 次而本地全绿 —— Nix 版本对重复属性的宽容度不同 {#nix-dup-attr-ci}

**症状:** `flake-check` 连续 8 次失败,而本地 `nix eval` 17 台全过、
`nix-instantiate --parse` 也过,怎么试都复现不出来。

**错误:**

```
error: attribute 'firewall' already defined at nixos/hosts/tank/system.nix:376:5
at nixos/hosts/tank/system.nix:250:3
```

文件里同时有:

```nix
networking.firewall.interfaces.tailscale0.allowedTCPPorts = [2049];   # 250 行
...
networking = { ... firewall = { ... }; ... };                         # 371-381 行
```

**根因是 Nix 版本差异,不是配置逻辑错。** 小实验:

```nix
{ a.b.c = 1; a = { b = { d = 2; }; }; }
```

- 本地 Determinate Nix 3.21.9 (2.34.8):**合并**成 `{ a.b = { c = 1; d = 2; }; }`
- CI 的 `cachix/install-nix-action@v27` 装的旧 Nix:**报错**

所以「本地绿、CI 红」而且本地无法复现 —— 差别不在代码,在跑代码的那个 Nix。

**修法:** 把同一个 `networking.firewall` 的定义合并到一个块里。tank 和 h610 各
有一处(h610 那处当时还没炸,是 tank 修好后的下一颗雷)。改完两台的 toplevel
drvPath **与改前逐一比对完全一致** —— 纯结构调整,语义零变化。

**留下的护栏:** 两个 firewall 块上面都写了「别在文件别处再写
`networking.firewall.xxx =`」。扫描全仓库的命令:

```sh
for f in $(find nixos -name "*.nix"); do
  b=$(grep -cE "^\s*networking\s*=\s*\{" "$f"); d=$(grep -cE "^\s*networking\.[a-zA-Z]" "$f")
  [ "$b" -gt 0 ] && [ "$d" -gt 0 ] && echo "$f"
done
```

**更值得记的一点:** 「我本地验过了」在这个仓库里不足以证明 CI 会绿 —— 本地是
Determinate Nix,CI 是 install-nix-action 的 stock Nix,两者对语法的宽容度不同。

---

## 2026-08-15 · 手机 QQ 图片转半天才出来 —— mihomo 静默丢掉了所有 QUIC {#quic-blackhole}

**症状:** 换到 mihomo 之后,手机 QQ 看图要转很久才出来。其它上网感觉正常。

**原因:** 规则第一条是无条件的
`AND,(NETWORK,UDP),(DST-PORT,443),REJECT` —— 把**所有** QUIC 都拦了。dae 时代
没有任何等价规则,是换 mihomo 引入的。

关键不在于拦,而在于**拦的方式是静默丢包**。实测从 LAN 往 UDP/443 发包,3 秒内
零响应、也没有 ICMP port unreachable。客户端拿不到「此路不通」的信号,只能把
QUIC 握手超时整个等完才回退 TCP —— 表现就是图片转半天然后突然出来。要是回一个
ICMP,客户端会毫秒级回退,根本察觉不到。

**影响面(r6s,一天):** 拦掉 22,074 个连接,其中 **42%(9,467 个)打的是国内
目标** —— 本来就该 DIRECT,拦它纯亏。被拦的里面有 `shquic.weixin.qq.com`(腾讯
自己的 QUIC 入口)、腾讯上海的 `101.227.133.99`、以及南京本地的 CDN 边缘节点
(单台设备一天撞 1,186 次)。

**排除掉的两个嫌疑:**

- *路由错了*:走代理的连接里一条腾讯域名都没有。QQ 拿图是直连 IP
  (`multimedia.nt.qq.com.cn`、`gchat.qpic.cn` 在 3 天日志里一次都没出现),
  匹配 `GEOIP(cn) → DIRECT`,正确。
- *中转性能*:同一个腾讯云 CDN 文件,LAN 客户端经 mihomo 中转 62 MB/s,比 r6s
  自己直连的 36 MB/s 还快。userspace 中转不是瓶颈。

**修法:** 拦 QUIC 的唯一理由是逼客户端回退 TCP(反向隧道对 UDP 支持差),而这个
理由**只对要进代理的流量成立**。所以按出口拆:每个 `,im` 的 GEOSITE 前面配一条
同域的 QUIC REJECT,兜底的 `MATCH,im` 前面再放一条无条件的;直连目标全部保留
QUIC。TCP 的规则顺序一条没动。

---

## 2026-08-15 · r6s 根从 eMMC 迁到 SD 卡,中途失联一小时 {#r6s-root-migration}

**影响:** 全家断网约一小时,人工拔电九次。

**背景:** r6s 的 eMMC 28G 只剩 12G,升 nixpkgs 时 `nixos-rebuild` 撞过 ENOSPC;
同时它 `life_time` 已经 0x03(用掉 20~30%),而 19.7 GB/天的写入里 92% 来自
journald(mihomo info 级日志 49 万行/天)。所以把根迁到一张 256G 的 SD 卡上。

**直接原因:步骤顺序错了。** 迁移脚本先做完 rsync 并卸载,**之后**才
`nixos-rebuild boot` 生成新一代。新一代的 closure 因此不在新根上,内核起来了、
f2fs 根也挂上了,但 `init=/nix/store/<hash>/init` 指向一个不存在的路径,卡死在
stage-1 —— 无头机器上表现为彻底失联。

验证方法(现在写进了迁移流程):

```sh
INIT=$(grep ^options /boot/loader/entries/nixos-generation-N.conf \
       | tr " " "\n" | grep ^init= | cut -d= -f2)
[ -x "/mnt/新根${INIT}" ] || 别重启
```

**为什么自动回退没生效(拔九次而不是三次):**

1. `bootctl set-oneshot` 在这块板子的 EDK II 上**不持久** —— 变量写进 efivarfs
   能读回,重启后就没了。第一次尝试因此根本没加载新一代,直接起了旧的。
   EFI 变量在这台机器上不可靠,只能用 ESP 上的**文件**机制。
2. 改用 boot counting(文件名 `nixos-generation-N+3.conf`)之后,又在
   `loader.conf` 里写了显式的 `default nixos-generation-114*`。**那个 glob 会把
   已经被标记为坏的条目也强行选中**,于是回退链失效。去掉 `default` 让
   systemd-boot 按自然顺序选(最高代且未标坏),3 次失败即自动回退。

**走过的两条弯路(都是错的,记下来免得重犯):**

- *以为是 ESP 撑满*。/boot 当时确实 91% 满,但比对 initrd 在 ESP 上和 store 里的
  大小是**完全一致**的,没有截断。
- *以为是 f2fs 模块没进 initrd*。`nix eval` 显示 `modules-load.d/nixos.conf`
  内容一直是对的;从 initrd 里提取失败是我的 cpio 用法有问题,不是配置问题。

**顺带查清的事实:**

- 卡实测:顺序写 48 MB/s、读 66 MB/s,4K 同步写 1630 IOPS(裸块)。持续写 6 GB
  全程钉在 48 MB/s,**没有 SLC 缓存崖**。
- 公平对比(都经文件系统)eMMC 反而更快:顺序 141 vs 46.5 MB/s、4K 同步写
  1075 vs 737 IOPS。**迁移的理由是空间和保护 eMMC,不是性能。**
- 迁移后 eMMC 写入归零,SD 上稳态约 9.7 GB/天 —— 比原来 eMMC 上的 19.7 低一半,
  和选 f2fs 的理由(log-structured 对 4 MB 擦除块写放大更低)方向一致。

相关:[r6s 恢复手册](runbooks/r6s.md)

---

## 2026-08-15 · SD 卡写入告警的阈值和窗口是怎么定出来的 {#sd-card-write-threshold}

**背景:SD 卡没有健康指标可读。** eMMC 有 `life_time` / `pre_eol`
(`/sys/block/mmcblk*/device/`),SD 卡什么都不暴露 —— 它是毫无预兆地坏。累计
写入量是唯一能拿到的磨损替代指标。

所以这条规则盯的是**速率异常**,不是绝对寿命。绝对寿命 Prometheus 存不住
(retention 90 天),要长期跟踪只能手工记账。速率异常才是能自动抓的:写入量
突然翻几倍意味着有东西在失控地写(跑飞的日志、重试循环),那才是真正会提前
烧掉卡的情形。

**阈值 40 GB/天的来历**(2026-08-15 实测全 fleet 稳态):

| 设备 | GB/天 |
|---|---|
| r6s mmcblk0(SD 根,f2fs) | 9.7 ← 最高的一台 |
| r2s mmcblk0 | 3.1 |
| r5s mmcblk1 | 2.2 |
| r6s mmcblk1(只剩 /boot) | 0.0 |

r6s 迁到 SD 之前在 eMMC 上是 19.7 GB/天(92% 来自 journald),也就是说"正常但
偏高"能到 20。取 40 = 稳态最高值的 4 倍、历史最坏值的 2 倍。

**窗口用 24h 不是 6h,这是拿真实数据试出来的。** 写完规则先在 h610 的
Prometheus 上跑了一遍:6h 窗口下 r6s mmcblk0 报 103 GB/天,直接触发 —— 那不是
故障,是当天迁移的两次 14GB rsync 加 6GB 写测试落在窗口里。6h 窗口 + `for 6h`
意味着一次大操作能让它响最多 12 小时。换 24h 窗口后同一时刻降到 25.7,不触发;
等那批写入滚出窗口会回到 ~10。

**教训:告警规则上线前拿实测数据验一遍**,否则第一周就把群刷炸,然后所有人
开始无视这个群。相关:[#r6s-root-migration](#r6s-root-migration)。

---

## 2026-08-15 · 这个 fleet 从来没跑过 GC,而补上的时候漏了 darwin 分支 {#nix-gc-never-ran}

**症状:** 升 nixpkgs 时 `nixos-rebuild` 撞 ENOSPC。

**根因:GC 一次都没跑过。** r6s 上实测 `nix-gc` / `nix-optimise` 两个 unit 是
`linked, ignored` —— 有 unit 文件、没 timer。8 代 generation 堆着,nix store
11G,而根分区总共才 28G。

**保留期取 30d 而不是原来注释里写的 1w:** generation 是出事时唯一的回退手段,
一周太短。30 天既能压住增长,又留得下足够的回滚余地。

`randomizedDelaySec` 是因为这些机器的 timer 会同时到点 —— h610 上并发的 GC
加上正在跑的构建,把内存打满过一次(见 `modules/monitoring/alerts.nix` 里
MemoryPressureHigh 那条)。

**当天的二次事故:漏了 darwin 分支,4 台 darwin 全部求值失败。** `modules/nix.nix`
被 `darwin/profiles/base.nix` 一起 import,而 nix-darwin 那边 `dates` /
`randomizedDelaySec` 根本没有对应选项(它用 launchd 的 `interval`),并且
`nix.gc.automatic` 要求 `nix.enable` —— 那几台跑的是 Determinate Nix,
`nix.enable` 是关的,GC 由它自己管。**本地只验了 nixos 就推了。** 这正是
AGENTS.md 里"逐台验证求值"那条规矩的由来。

---

## 2026-08-14 · 开一个交互 zsh 要 1458ms —— 两个 compinit 互相判废对方的 dump {#zsh-double-compinit}

**症状:** 这台 mac 上开一个交互 zsh 要 1458ms,其中约 1170ms 是补全缓存**每次
启动都在重建**。

**根因:有两个 compinit 抢同一个 `~/.zcompdump`。**

1. nix-darwin 的 `/etc/zshrc`(`programs.zsh.enableCompletion`)跑一次
2. home-manager 生成的 `.zshrc` 再跑一次

两次之间 home-manager 往 `fpath` 里塞了插件目录,所以第二次数到的文件数和第一次
不一样。而 compinit 复用 dump 的条件正是「dump 头一行记的文件数 == 这次数到的」
—— 于是两边永远互相判定对方的 dump 失效:每开一个 shell 就重扫三千多个补全
文件、重写 89KB 的 dump 两遍。给 home-manager 那次一个 `-d` 指向**自己的** dump
文件,两边就不打架了。

**fpath 里还有一堆重复目录:** `~/.nix-profile`、`/run/current-system/sw`、
`/nix/var/nix/profiles/default` 三条路径指向 store 里同一份 zsh(各 1233 个
文件),macOS 上还要再算一份自带的 `/usr/share/zsh/5.9` —— 跟正在跑的 5.9.1
都不是同一个版本。`typeset -U` 去不掉,因为路径字符串本身不同。

**去重时只拿解析后的真实路径当 key,保留原来的写法。** 直接把 fpath 换成
`/nix/store/...` 的真实路径会出事:compaudit 判断安全性时会一路检查父目录,走到
group-writable 的 `/nix/store` 就把整个 fpath 判成 insecure,于是系统那份
compinit 弹出交互确认 —— 在没有 tty 的嵌套 shell 里直接 "initialization
aborted"。而 `~/.nix-profile/...` 这种写法它只看软链本身,不会走到 `/nix/store`。

`-C` 是在此之上再跳过"有没有新补全"的扫描。代价是装了新工具 dump 不会自己更新,
所以配了 activation 在每次 home-manager 切换后删掉它。

---

## 2026-08-09 · tank 的默认构建并发是灾难性超额订阅 {#tank-build-concurrency}

**症状:** 一次 ARM 构建期间,tank 上 load1 = 42、CPU 93%、47 个 `qemu-aarch64`
进程,连 node_exporter 的抓取都从 ~20ms 涨到 **504ms**。

**机制:** 默认值在这台上是超额订阅(和它是不是构建机无关,自己编东西也一样):

```
max-jobs = auto  → nproc = 20,而这是 E5-2666 v3,10 物理核 / 20 线程
cores    = 0     → 每个构建再用满 20
```

最多 20 个并发构建 × 每个 20 路并行 = 400 个进程抢 10 个核。

**关键在于这不是"用满硬件",而是比不超额还慢** —— 上下文切换的开销吃掉了并行
收益。ARM 构建全是 QEMU 用户态模拟,纯 CPU 密集、吃执行单元,SMT 在这种负载下
几乎没有增益,按线程数配等于按两倍物理核配。

**修法:** 6 × 2 = 12 路并行,略高于 10 个物理核(构建有一部分时间在等 I/O),
剩下的留给这台上跑着的 matrix-synapse、postgres、minecraft、samba、
Prometheus/Grafana。

---

## 2026-08-09 · h610 摘掉 binfmt —— 问题是溢出,不是抢跑 {#h610-drop-binfmt}

h610 以前是 deploy-rs 的构建机,靠 QEMU 模拟给 r6s/rpi4/r5s 那几台 SBC 编闭包,
那个角色已经交给 tank 了。摘掉 binfmt 的理由**是溢出,不是"抢在 tank 前面"**。

**nix 的调度本来就是远程优先:** `derivation-building-goal.cc` 先问 build hook,
hook 在 tank 有空闲 slot 时就 accept,所以 ARM 构建本来就会去 tank。

**但 binfmt 会把 `aarch64-linux` 加进 `extra-platforms`**,于是
`build-remote.cc` 里的 `couldBuildLocally` 为真;一旦 tank 的 16 个 slot 全占满,
hook 返回 **decline 而不是 postpone** —— 溢出的 ARM 构建就落到这台 12 核 /
15 GiB 的机器上用 QEMU 跑。那是最坏的组合,而这台当天已经 OOM 两次。

摘掉之后那种情况变成 postpone(排队等 tank),不再有慢速回落。**代价:** tank
不可达时这台编不了 ARM(直接失败而不是慢慢磨),`just build-local <arm-host>`
在这台上也不再可用 —— 那条路本来就慢到没有实用价值。

相关:[#tank-build-concurrency](#tank-build-concurrency)。

---

## 2026-08-09 · deploy 改成在目标机构建 {#deploy-remote-build}

**默认(`remoteBuild = false`)是发起方组装完整闭包再 `nix copy` 过去**,那意味着
发起方要把目标平台的全部产物在本地物化一遍。实测 `deploy .#r6s`:发起方要下载
641 MiB / 549 个路径,而这些路径 **r6s 自己已经有 88%**(上一代 generation
留下的)。抽样 60 个"待下载"路径,r6s 上有 53 个,h610 上一个都没有。

**这部分开销 remote builder 帮不上忙** —— 那些路径是缓存命中的**下载**不是构建,
而 `buildMachines` 只 offload 构建。

顺带解决另一件事:ARM 目标机原生构建比拿 x86 机器 QEMU 模拟快得多。实测同一个
derivation(drv 哈希一致),r6s 原生 4.3s,tank 模拟 15.7s —— 快 3.7 倍,尽管
tank 有 20 线程而 r6s 只有 8。

**代价:** 目标机得自己扛构建。对 rpi4 这种弱机,遇到真要编的大东西会慢。

**⚠️ 当前状态和上面这段结论相反,注意别被误导。** `lib/mkDeployNodes.nix` 里那行
现在是注释掉的(commit `0645dfa` "disable remote build and added dev on marble"
把 `remoteBuild = true;` 改成了 `# remoteBuild = false;`),而 deploy-rs 的默认
值就是 false。**所以现在实际是在发起方构建。** 后果:从 mac(aarch64-darwin,
没有 builders)部署任何 linux 主机都必须显式加 `--remote-build`,否则会尝试本地
构建 x86_64-linux 然后失败。2026-08-16 踩到一次。

---

## 2026-08-08 · headscale 的 SSH 策略有三个坑,照抄 tailscale 官方示例会踩 {#headscale-ssh-policy-traps}

策略在 `nixos/hosts/h610/system.nix` 的 headscale `policy` 里(`ssh` 段)。

**1. `dst` 不能用 group。** headscale 的校验里 Group 不是合法的 SSH destination
(实测报 `alias *v2.Group is not supported for SSH destination`)。允许的是 tag、
`autogroup:self/member/tagged`,以及"同一个人自己的用户名"。

这里用 `autogroup:member` —— 它是"所有用户拥有的非 tag 节点",正好覆盖全部机器,
**不需要给节点打 tag**。打 tag 反而会出事:tag 化的节点不再属于
`group:imdomestic`,上面那条 acl 的 `dst` 就匹配不到它们了。(同一个陷阱在
headplane agent 的 pre-auth key 上又出现了一次 —— 那把 key 也不能带 `--tags`。)

**2. `action` 必须是 accept,不能是 check。** check 要求发起方每隔一段时间
(默认 12 小时)在浏览器里重新认证一次,会直接打断 deploy-rs 和远程构建这类
非交互场景。

**3. `headscale policy check` 是必要条件不是充分条件。** 实测它能抓住第 1 条
(类型错误),但 `action: "check"` 和**漏写 `users`** 这两种它都照样报
"Policy is valid" —— 尽管源码里就有 `ErrSSHUsersMustBeSpecified`。**校验过了
不等于行为符合预期。**

改这一段要 rebuild + switch h610(策略是 nix store 里的文件)。需要频繁调试时
可以临时切 `policy.mode = "database"` 用 `headscale policy set` 热更新,定稿再
切回来。

---

## 2026-08-08 · tailscale SSH 在 r6s 上的实测行为 {#tailscale-ssh-r6s-probe}

记在这里免得以后重新推一遍。

- **不带任何密钥**(`IdentityFile=/nonexistent` + `IdentityAgent=none`)能以 root
  登进去 —— 认证确实走 tailnet 身份。
- **带密钥的 ssh 也照常能连**,但日志显示它同样是 tailscaled 处理的,只是策略
  放行了 —— 那把密钥根本没被用到。
- **来自 wireguard 地址(10.0.0.x)的连接仍然走 sshd**,publickey 认证,完全不受
  影响。**这是永远的退路。**
- 附带好处:tailscaled 会记 `audit: SSH login: user=root ...
  ts_user=hank@imdomestic.com node=h610...`。以前四个人共用一份 master
  authorized_keys 登 root,日志里分不出是谁,现在分得出。

一旦某台开了 `--ssh`,**从 tailnet 地址过去的 22 端口就由 tailscaled 接管**,
成败改由 headscale 的策略决定,带密钥也救不回来 —— 所以策略要先落地、节点后开。
策略本身的坑见 [#headscale-ssh-policy-traps](#headscale-ssh-policy-traps)。

---

## 2026-08-08 · Grafana 数据源加了 uid 之后整个服务起不来 {#grafana-provisioning-uid}

**症状:** 给数据源加上 `uid = "prometheus"` 之后 Grafana 直接起不来,浏览器
"refused to connect",而 Prometheus 和 Alertmanager 还好好的 —— 很容易往网络
方向排查。

**根因:** 给一个**已经存在于 `grafana.db` 里的**数据源改 uid,provisioning 会
报 "data source not found" —— 它按新 uid 去找要更新的记录,而库里那条是旧的
随机 uid。

**而 Grafana 把 provisioning 失败当致命错误,不是警告。** 数据源配错、看板
JSON 不合法,都会让整个服务拒绝启动。

**修法:** provisioning 里长期留一条"先删同名的再建",而不是手动删一次 ——
tank 万一从旧的 `grafana.db` 恢复,同样的冲突会再来一遍。删掉再建对一个纯声明式
的数据源没有任何代价:它不存查询、不存状态,uid 又是钉死的,看板的引用不会断。

---

## 2026-08-08 · r6s 和 rpi4 之间的直连只能走 IPv6,而隐私扩展会把它周期性打断 {#r6s-rpi4-ipv6-privacy}

**IPv4 直连在这一对之间结构性不可能。** 两边的 WAN v4 都是电信 CGNAT 地址
(r6s `100.84.115.12`,rpi4 `100.112.172.41`),双双落在 `100.64.0.0/10` 里,于是
互相被对方 tailscale 的反欺骗规则丢掉:

```
ip saddr 100.64.0.0/10 iifname != "tailscale0" drop
```

(同一条规则的另一个症状见 `modules/singbox` 里 autoRedirect 的说明。)

**所以只剩 IPv6,而隐私扩展会让临时地址定期轮换**,tailscale 通告出去的端点跟着
失效,直连就周期性断掉回落到 DERP。实测抓到过:r6s 把 rpi4 钉在
`2409:8a20:1951:a350:...` 上,而那时 rpi4 的首选临时地址已经换到
`2409:8a20:1905:228f` 前缀了 —— 用的是一个**还没过期但已不是首选**的旧地址,
等它彻底失效这条直连就断。

**取舍:** 隐私扩展防的是"通过接口标识符追踪这台设备",但这是路由器自己的 WAN
地址,运营商给的前缀本来就标识了这条线路,标识符稳不稳定几乎不增加暴露面。换来
唯一可用的直连路径不再周期性抖动。前缀本身仍会在 PPPoE 重拨时变,那躲不掉,但比
每天一次的临时地址轮换少得多。

---

## 2026-07-31 · dae 劫持 DNS,导致 lego 的 DNS-01 永远失败 {#dae-breaks-lego-dns01}

**影响:** h610 和 shanghai 从 7/31 起拿不到真证书,每天定时器跑一次、每次都是
`propagation: time limit exceeded ... NS ophelia.ns.cloudflare.com.:53 returned SERVFAIL`。

**根因不在 acme 也不在 Cloudflare,在 dae 劫持 DNS。** dae 把所有 53 端口流量按
自己的 `dns.routing.request` 改道(当时 `fallback: alidns`),**目的地址被丢弃**
—— 除非规则显式写 `-> asis`。而 lego 的传播检查恰恰是「绕开递归缓存、直连权威
NS 问一遍」,这个前提被 dae 拆掉了。

同一条 dig,应答标志一眼看出区别:

```
h610 / shanghai (dae 开) : flags: qr rd ra      ← 递归解析器答的
r5sjp           (dae 关) : flags: qr aa rd      ← 真·Cloudflare 权威
```

于是 lego 的「问权威 NS」实际问到了 alidns,而 alidns 去查一条刚建几秒、
Cloudflare 托管、带 DNSSEC 的记录会返回 SERVFAIL,重试满 2 分钟后放弃 ——
从没让 LE 去验证过。手动「停 dae → 跑 order → 开 dae」能成,就是因为停掉之后
劫持消失。

**修法:** `--dns.propagation-wait 120s` 让 lego 完全不探测,固定等 120s 再让 LE
去验。LE 在境外,那里没有 dae。120s 是在 shanghai 上拿 LE staging 实测过的。

**不要用 `dnsPropagationCheck = false`:** 它展开成 `--dns.propagation-disable-ans`,
是把检查整个取消而不是换一种做法 —— lego 建完记录 2 秒就让 LE 去验,记录还没生效
→ NXDOMAIN。而且这两个标志互斥。

**后果不只是「少一张证书」:** shanghai 上 derper 会拿 NixOS 生成的自签占位证书
照常启动,而节点选 home DERP 只看 UDP 3478 的 STUN 延迟 —— 那个是通的。于是
tank/rpi4/r5s 都把 shanghai 选成了 home DERP,再连 TLS 时被拒。**一个证书坏掉的
DERP 比没有 DERP 更糟 —— 它会把节点吸过来再拒绝服务。**
