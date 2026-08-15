# r6s 恢复手册

r6s 是**这个家唯一的出口**(PPPoE 拨号 + mihomo 透明代理 + LAN 网关,
`192.168.22.1`)。它挂了全家没网,而且它是无头的 —— 出问题时你多半连不上它,
也看不见引导菜单。

**这份文档你需要它的时候大概率打不开这个仓库。想清楚要不要打印一份贴在机器旁边。**

## 一分钟速查

| 症状 | 先做什么 |
|---|---|
| 全家没网,r6s ping 不通 | 拔电重插,等 2 分钟。最多重复 3 次 —— boot counting 会自动回退 |
| 拔了 3 次还是不行 | 接 HDMI + USB 键盘,开机后一直按 ↓ 停住倒计时,选 `NixOS 救援 - eMMC 上的 ext4 根` |
| 连得上但没网 | 先看 `systemctl is-active mihomo systemd-networkd`,再看 `ip -br addr show ppp0` |
| 看不到引导菜单 | 串口:ttyS2,**波特率 1500000**,8N1 |

## 硬件与存储布局

```
mmcblk1  28.9G  eMMC(焊死)
├─p1        8M  u-boot
├─p2      600M  vfat  /boot ← ESP,systemd-boot 从这里读内核和 initrd
└─p3     28.3G  ext4  未挂载 ← 2026-08-15 之前的根,完整保留,是回退目标

mmcblk0   239G  SD 卡(可插拔)
└─p1      239G  f2fs  /    ← 当前的根
```

引导路径:UEFI(EDK II)→ systemd-boot(在 eMMC 的 ESP 上)→ 读内核+initrd
→ initrd 挂 SD 卡上的 f2fs 根。**引导器全程不需要认识 f2fs**,所以 SD 卡只装根。

## eMMC 救援入口

SD 卡是消耗品且**不暴露任何健康信息**(eMMC 有 `life_time`/`pre_eol`,SD 卡没有,
它是毫无预兆地坏)。所以 eMMC 上的旧根原样留着,并且有一个不受 NixOS 管理的
引导入口指向它:

```
/boot/EFI/rescue/kernel.efi              ← 从 generation 112 的文件复制
/boot/EFI/rescue/initrd.efi
/boot/loader/entries/rescue-emmc.conf
```

菜单里显示为 **`NixOS 救援 - eMMC 上的 ext4 根`**。

**为什么它是命令式的、配置里没有:** `extraFiles` 要引用 store path,而 gen112 的
initrd 会被 `nix.gc` 在 30 天后回收;`builtins.storePath` 在 flake 纯求值里用不了,
而且求值发生在发起方(macOS),那台机器上根本没有这个路径。

**三个关键细节(改动时别踩):**

- `init=` 必须钉死 gen112 的 toplevel,**不能**用 `/nix/var/nix/profiles/system`
  符号链接 —— eMMC 根上的 profile 已经被当初的 `nixos-rebuild boot` 推到了 114,
  而 114 的 fstab 写的是 f2fs 的 UUID。用符号链接的话,救援系统会拿着一份
  「根应该是 f2fs」的配置去跑,卡真坏了的时候正好废掉。
- `sort-key` 用 `a-rescue`,排在 `nixos` 前面,所以不会被选成 default。
- 文件放 `/boot/EFI/rescue/` 而不是 `/boot/EFI/nixos/`(后者会被
  `configurationLimit` 裁剪)。实测扛过 `nixos-rebuild switch`。

**重建步骤:**

```sh
# 找一个 root=ext4 的 generation(引导条目里 init= 指向的 toplevel 要在 eMMC 根上)
mkdir -p /boot/EFI/rescue
cp /boot/EFI/nixos/<kernel>.efi /boot/EFI/rescue/kernel.efi
cp /boot/EFI/nixos/<initrd>.efi /boot/EFI/rescue/initrd.efi
cat > /boot/loader/entries/rescue-emmc.conf <<'EOF'
title   NixOS 救援 - eMMC 上的 ext4 根
sort-key a-rescue
linux   /EFI/rescue/kernel.efi
initrd  /EFI/rescue/initrd.efi
options init=/nix/store/<gen112-toplevel>/init root=fstab loglevel=4 lsm=landlock,yama,bpf
EOF
```

验证 initrd 指向的是 eMMC 而不是 SD:

```sh
zstd -dc /boot/EFI/rescue/initrd.efi | grep -c 91dd2c0a-58ca-4d28-846d-a608244aa146  # eMMC,应为 1
zstd -dc /boot/EFI/rescue/initrd.efi | grep -c 99e8c9ba-539f-45a2-8b80-aecebef9a1af  # SD,应为 0
```

> **状态:入口已建、已确认能被 `bootctl` 识别、扛过一次 switch,但尚未做启动验证。**
> 哪天顺手重启时选一次确认。

## 引导相关的两个坑

**EFI 变量在这块板子上不可靠。** `bootctl set-oneshot` 写进 efivarfs 能读回,
但重启后就没了 —— 所以「只让下一次启动试新配置」这招在这台机器上**不成立**。
只能用 ESP 上的文件机制(`loader.conf` 的 `default`、boot counting 的文件名)。

**不要在 `loader.conf` 里写显式的 `default nixos-generation-N*`。** 那个 glob 会把
已经被 boot counting 标记为坏的条目也强行选中,自动回退就失效了(实测因此拔了
九次电才回去)。去掉 `default` 让 systemd-boot 按自然顺序选:最高代且未标坏。

boot counting 的用法:把条目改名成 `nixos-generation-N+3.conf`(3 次机会)。
每次尝试 systemd-boot 会改名递减;成功启动后 `systemd-bless-boot` 会把计数清掉。

## 换根 / 迁移的检查清单

血泪来源:[2026-08-15 的迁移](../incidents.md#r6s-root-migration)。

1. **rsync 必须排在 `nixos-rebuild boot` 之后**,否则新一代的 closure 不在新根上
2. 重启前必须验证 `init` 真的存在:
   ```sh
   INIT=$(grep ^options /boot/loader/entries/nixos-generation-N.conf \
          | tr " " "\n" | grep ^init= | cut -d= -f2)
   [ -x "/mnt/新根${INIT}" ] || 别重启
   ```
3. 整条 closure 都要在:`for p in $(nix-store -qR $(readlink -f /nix/var/nix/profiles/system)); do [ -e /mnt/新根$p ] || echo 缺: $p; done`
4. 卸载后跑一遍 `fsck`,确认 checkpoint 是干净的 unmount
5. 用 boot counting,不要用 `set-oneshot`
6. 人在机器旁边再重启

## 部署

正常走 `deploy .#r6s`。**发起方在手机热点或网络受限时会失败** —— deploy-rs 在
macOS 上要调 `api.flakehub.com` 拿 Native Linux Builder。这时改用:

```sh
nixos-rebuild switch --flake .#r6s \
  --build-host root@100.64.0.5 --target-host root@100.64.0.5
```

在 r6s 本机构建,不依赖发起方的构建能力。

`just deploy-system r6s` 会跑 flake checks,而 checks 里的 `dtbs-filtered` 在
aarch64-darwin 上构建失败 —— 加 `--skip-checks`。**注意 `just` 的退出码会被管道
吞掉,别只看退出码就以为部署成功了。**
