# 事故与排查记录

代码里放"这行为什么这么写",这里放"那次到底怎么回事"。

判据:如果一段注释回答的问题不是「读者盯着这行时会冒出来的」,它就该在这里。
典型的是根因调查过程、当时的实测数据、试过但走不通的路。代码里只留一行指针。

按时间倒序。每条给一个锚点,代码里用 `docs/incidents.md#<锚点>` 引用。

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
