# 决策记录

这里放**「某样东西为什么不在」**。

这类说明没有可以依附的代码行 —— 一个被删掉的服务、一个故意不开的选项,在配置里
是一片空白,而空白处贴不了注释。硬塞在附近某行上面只会让那行显得莫名其妙。

反过来,「这一行为什么这么写」应该留在那一行旁边,不要搬到这里。

按时间倒序。代码里用 `docs/decisions.md#<锚点>` 引用。

---

## 2026-09-03 · WSL 的默认模型名给 262K,84K 作为 fast 档 {#wsl-ninfer-default-262k}

公开 API 的 `qwen3.8-27b` 指向 groupwise-int 权重、NVFP4 KV、262K context、
Vision4K 和 MTP3,也是 NixOS 自动启动的常驻档。原生 NVFP4 权重的 84K 配置保留为
`qwen3.8-27b-fast`,它有更快的 Prefill 和更大的 Vision8K 预算。用户显式选择让最大
上下文成为无后缀默认值;因此客户端只在更看重速度或图片预算时才需要换模型名。

两档不能同时驻留显存,由 llama-swap 在收到请求时自动停止旧 OCI unit、启动目标
unit。API 地址始终是 Tailnet 的 `100.64.0.14:8000`,切换不要求客户端改 base URL。
完整内存账见 `docs/incidents.md#wsl-ninfer-24g`,网关链路见
`docs/incidents.md#wsl-ninfer-model-gateway`。

---

## 2026-09-01 · rpi4 从 portal 改成 bridge {#rpi4-portal-to-bridge}

rpi4 原本是六台 portal 之一:国内客户端连它的 `client-in2`(54322),流量经反向
隧道到 r5sjp,从日本出去。搬到悉尼之后这个身份**已经名存实亡**,只是没人去
删 —— 它在 hotspot 的 NAT 后面,没有任何公网入口;`ddns-go` 也早关了,而
`rpi4.imdomestic.com` 还留着一条指向它国内旧地址的 AAAA。

于是在此之前的一段时间里,r5sjp 一直在重试拨一条死链
(`rpi4.imdomestic.com:2444`),订阅里有一个连不上的节点,dae 的 `im` 组里也有
一个死节点在参与选路。这次一并删掉。

**改成 bridge 而不是修好 portal,是因为 portal 这个角色它当不了。** Xray 反向
代理的两端分工是固定的:portal 是有公网入口、被拨的那端;bridge 是主动拨出去
的那端,不需要任何入站可达性。悉尼这条线正好只满足后者 —— 这也正是 r5sjp 一直
用 bridge 的原因,它挂在 NTT 消费线上,同样没有稳定公网入口。

所以现在有两条反向隧道,方向一致(国内 portal ← 境外 bridge),出口不同:

- `reverse-<h>.hank.internal` → r5sjp(日本),客户端口 54322
- `reverse-<h>-au.hank.internal` → rpi4(悉尼),客户端口 54324

**只接 h610 和 sh 两台。** 其余几台 portal(r5s / r6s / r2s)的 ddns-go 只发
AAAA,而悉尼那条线没有 IPv6,拨不过去 —— 加进去只会再造几条死链。

## 2026-09-01 · 两个出口各有自己的自动组,绝不合并 {#au-exit-separate-auto-group}

每个客户端里是**两个**自动测速组,不是一个:

| | 日本出口 | 悉尼出口 | 手动选择组 |
|---|---|---|---|
| clash / imsub | `auto-jp` (url-test) | `auto-au` (url-test) | `im` (select) |
| Egern | `AUTO-JP` (smart) | `AUTO-AU` (smart) | `PROXY` (select) |
| mihomo | `auto-jp` | `auto-au` | `im` (select) |
| sing-box | `auto-jp` (urltest) | `auto-au` (urltest) | `im` (selector) |
| dae | `im` 组 | `au` 组 | 无(靠 routing 规则指) |

**组内自动择优,跨出口只手动切。** 理由是自动组比的全是延迟,而这两条线上
延迟和吞吐是**反的**。同一台 h610、同一时刻、同一目标实测:

| 目标 | 日本出口 54322 | 悉尼出口 54324 |
|---|---|---|
| AARNet 镜像(在悉尼) | **39 Mbps** | 13 Mbps |
| Cloudflare | **132 Mbps** | 18 Mbps |

连目标就在悉尼的时候,日本出口都快 3 倍。而同一时刻 dae 的延迟检查里,悉尼组
是 446–564ms 且稳定,日本组在 0.7–2.9s 之间反复判死判活 —— **按延迟看悉尼明显
更优,按吞吐看它差 3 到 7 倍**。合成一个自动组,悉尼会稳定胜出,然后把一切拖垮。

所以悉尼出口的定位是**冗余 + 一个澳洲 IP**,不是性能。要用澳洲 IP 或者日本那条
挂了,手动切 `auto-au`;平时留在 `auto-jp`。

dae 那边还有一个额外的坑值得单独记:`im` 组是靠 `name(keyword: 'imdomestic')`
筛的,所以那两个节点在 dae 里**故意不叫 `imdomestic-*`**,叫 `au-h610` /
`au-sh`。哪天有人为了"统一命名"把它们改回去,它们会**静悄悄地**混进 im 组,
不报任何错。

隧道段的带宽数据见 docs/incidents.md#syd-jp-relay-beats-direct。

---

## 2026-08-31 · rpi4 摘掉 dae {#rpi4-drop-dae}

这台搬到悉尼之后 dae 是**净损害**,所以从 `imports` 里摘了。另外八台
(shanghai/tank/x470/h310/h610/r2s/r5s/r6s)照旧,它们在国内,那套规则是对的。

那套规则的前提是「人在国内,需要翻墙出去」:`fallback: im`,而 im 组是经
六个国内 portal 的反向隧道到 r5sjp(日本)。人到了悉尼,这个前提整个翻转:

**公寓网络的国际线路极好。** 本地有 Google Global Cache —— `ping
www.google.com` 是 **0.7ms**(走 IPv6,`2001:4860:...`),1.1.1.1 / 8.8.8.8
同样 0.7ms 左右,Telstra 悉尼 1.1ms 作参照。国际主流服务基本是本地落地的。

**而 dae 把这条线路绕成了 悉尼 → 国内 portal → 日本 → 目标。** 同一时刻
的 A/B(规则里 Apple/Microsoft 判 direct、Google/GitHub 判 im,四个都是
国外站):

| 目标 | dae 判定 | `curl` total |
|---|---|---|
| apple.com | direct | 0.12s |
| microsoft.com | direct | 0.27s |
| google.com | im | 2.90s |
| github.com | im | 3.91s |

**10 到 30 倍。** 注意 `time_connect` 看不出来(5~7ms),因为透明代理的 TCP
握手是和本地 dae 完成的 —— 只有 `time_total` / `time_starttransfer` 才暴露
真实路径,拿 connect 时间判断代理健康度会得出完全相反的结论。

到国内确实慢(晚高峰 `sh.imdomestic.com` 452ms),但那是上游 Superloop 的
transit 决定的,不是 dae 能救的 —— 恰恰相反,im 组要先绕回国内再去日本,
比直连更远。那条路的形状见 docs/incidents.md#syd-cn-route-via-europe。

## 2026-08-31 · rpi4 不再拨 PPPoE,ddns-go 也停了 {#rpi4-drop-pppoe}

这台 2026-08-31 从国内搬到悉尼的公寓,上游性质彻底变了:原来是自己拨号
(`services.pppd` 的 `chinamobile` peer,PPPoE over `enp1s0u2`),现在是插墙口吃 DHCP,
再过一道 captive portal。

**删掉的:**

- `services.pppd` 整块。PPPoE 的凭据是运营商宽带账号,换了国家就没有对应的东西了;
  留着一份拨不上的 peer 只会让 `maxfail 0 / holdoff 5` 无限重试刷日志。
  WAN 现在是 `20-wan-uplink` 里的 `DHCP = "yes"`,认证交给
  `my.captivePortal`(表单怎么来的见 docs/incidents.md#rpi4-sydney-captive-portal)。
- `25-wan-ppp` 那份 network。它 match 的 `ppp0` 不会再出现。
- `30-br-lan` 的 `IPv6SendRA` / `DHCPPrefixDelegation`。这两个原来是把 PPPoE 拨到的
  `::/60` 往 LAN 分一段,而公寓 hotspot 只给一个 NAT 后的 v4 地址,没有前缀委派。

**停掉但没删的:** `ddns-go`。它盯的 `netinterface: ppp0` 已经不存在,而且这台现在
整个在 hotspot 的 NAT 后面 —— WAN 地址是 `172.24/16`,也没有全局 IPv6,
把这种地址推到 `rpi4.imdomestic.com` 毫无意义。配置整份留在文件里,
`enable`/`wantedBy` 两行翻回来就能恢复,所以没必要为了"干净"把它删了再抄回来。

**连带失效、但这次没动的:** `services.xray` 的两个 inbound(2444 / 54322)和
wireguard 的 `10.0.0.6` —— 在 NAT 后面收不到入站连接。它们只是白监听,不报错也不
拖别的东西下水,等确定这台在悉尼要扮演什么角色再一起处理,不在这次改动范围里。

## 2026-08-31 · 删掉 LS_COLORS {#drop-ls-colors}

`home.sessionVariables.LS_COLORS` 原来是一条 1.8k、115 条规则的字符串,来自
trapd00r/LS_COLORS,当年连同别人的 dotfiles 一起原样抄进来的,从来没有人按自己
的口味改过一条。

**它自带一套 256 色板,和终端主题是脱钩的。** 里面写死的是 `38;5;40`(#00d700
绿)、`38;5;220`(#ffd700 黄)、`38;5;208`(#ff8700 橙)这类立方色号,不走终端
的 16 色调色板 —— 终端主题怎么换,这些颜色都纹丝不动。

**净收益经不起量:** 拿 30 个文件的样本树用 eza 实测,不设 LS_COLORS 时 21 个
文件有颜色、且全部落在终端调色板上;设了之后 22 个有颜色,其中 6 个
(`*.7z` / `*.tar.gz` / `README.md` / `LICENSE` / `*.sh` / 断链)是上面那套板外
硬编码色。也就是多点亮一个文件,换来六个游离在主题之外的颜色。

**最初的误判是以为它管 `ls`。** 实际的消费者是 eza(`ls` 别名和 chpwd hook)、
zsh 补全、fzf-tab、nushell;GNU `ls` 在这台机器上根本没人调用。而 eza 在
LS_COLORS 缺席时会退回自己的默认配色,用的是基本 ANSI 码 —— 所以删掉不是变成
没颜色,是变成跟着主题走的颜色。

同时删掉 `init-extra.zsh` 里的 `zstyle ':completion:*' list-colors
${(s.:.)LS_COLORS}`:值没了之后这条只会把补全菜单的颜色设成空,留着是误导。

---

## 2026-08-12 · 删掉 cockpit {#drop-cockpit}

**在 NixOS 上它 15 个页面里大部分没有后端。** h610 上实测 `pkcon` / `nmcli` /
`udisksctl` / `sosreport` / `setenforce` 全部 MISSING,于是 apps、packagekit、
networkmanager、storaged、sosreport、selinux 六页全是死的。剩下能用的
shell / systemd / metrics 三页,这个 fleet 里分别有 ssh、node_exporter 的
systemd collector、和 Prometheus 做得更好。

**users 页更糟,而且是理念相反而不是打包问题。** 全 fleet `mutableUsers = true`,
在 cockpit 里改一个 `users.users` 声明过的用户,下次 switch 会被静默改回去 ——
不报错,就是没了。cockpit 的前提是「用 GUI 改一台可变的机器」,NixOS 的前提是
「改配置再重建」。

**实际使用情况印证了这一点:** h610 和 r6s 早就各自 `mkForce false` 掉了,而还
开着的 r5s / shanghai 三十天日志零条。

**它还是「服务只绑 tailscale」这条规矩的唯一例外**,而且三个最不该例外的选项凑齐
了:`openFirewall = true` + `allowed-origins = ["*"]` + `AllowUnencrypted = true`,
实测监听在 `[::]:9090`。而 r5s 有 WAN + PPPoE、shanghai 是公网 VPS,两台都
`firewall.enable = false`。对比 `modules/telemetry/default.nix` 里那条「绑定地址
是唯一真正起作用的边界」。

**遗留:** Prometheus 当初为它让到 9009(见 `modules/monitoring` 的 port 选项)。
那个理由现在不成立了,但 9009 已经写进两份配置和看板,不值得再挪回去。

---

## 2026-08-12 · rpi4 上清掉 niri + firefox 桌面栈 {#rpi4-drop-desktop}

树莓派是那个 LAN 的网关(`192.168.20.1`),没接显示器,那套桌面栈**从来没人用
过** —— 纯历史遗留。

它当时拖进 system closure 的东西(实测 narSize):

| 包 | 大小 | 怎么进来的 |
|---|---|---|
| mbrola-voices | 645 MiB | etc → speech-dispatcher → mbrola → voices |
| llvm-21.1.8-lib | 532 MiB | tmpfiles → graphics-driver.conf → mesa → llvm |
| firefox-unwrapped | 356 MiB | system-path → firefox |
| nautilus | 277 MiB | etc → dbus-1 → nautilus |
| mesa | 260 MiB | graphics-drivers |
| speech-dispatcher + flite | 120 MiB | |

645 MiB 的语音合成音色库,在一台当路由器用的树莓派上 —— 那是 niri 带的
xdg portal / a11y 那一串的末端。

**配置里留下的 `gdm`/`gnome` 两个显式 `false` 是有意的:** 它们是「这台不要桌面」
的意图声明,不是对某个 profile 的覆盖(rpi4 的 profile 列表里 desktop 本来就是
注释掉的)。真有人哪天手滑加回 desktop profile,那两行会挡一下。
