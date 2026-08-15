# 决策记录

这里放**「某样东西为什么不在」**。

这类说明没有可以依附的代码行 —— 一个被删掉的服务、一个故意不开的选项,在配置里
是一片空白,而空白处贴不了注释。硬塞在附近某行上面只会让那行显得莫名其妙。

反过来,「这一行为什么这么写」应该留在那一行旁边,不要搬到这里。

按时间倒序。代码里用 `docs/decisions.md#<锚点>` 引用。

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
