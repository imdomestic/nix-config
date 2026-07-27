# tank: 系统盘 sdd(ext4) → bcachefs (sdc ssd.fast + sda hdd.14t)

分支：`tank-root-on-bcachefs`（配置已改好，`nix eval` 通过，**尚未部署**）

```
现状                                   目标
sdd1 1G  vfat  /efi (GRUB)      →  sdd1 1G  vfat  /boot  (systemd-boot, 唯一留在 sdd 上的东西)
sdd2 237G ext4 /                →  Phase 1 保留当救援；Phase 2 → 16G swap + ~220G 并入 ssd.fast
sdc  233G      bcachefs ssd.fast┐  →  /   (fs 根直接当系统根)
sda  12.7T     bcachefs hdd.14t ┘     原 /data 内容搬进 fs 根的 data/ 子目录，
                                       所以 /data/nas、/data/lib/postgresql… 路径全部原样保留
sdb  466G      Windows          →  不动（走固件 F11/F12 进 Windows）
```

要复制的数据：/nix 126G + /home 23G + /var ~5G ≈ **155G**（/var/lib 那 17G 里 16G 是 swapfile，不复制）

---

## Phase 0 — 开工前必须准备

- [ ] **生成 initrd 救援 sshd 的专用 host key**（远程操作的话这是命根子，见下）
- [ ] `/data/nas` 里的重要数据、postgres/mysql 有单独备份（迁移动了它们的父目录）
- [ ] 如果人在现场：做一个 NixOS 安装 U 盘插上。tank 没有 IPMI/BMC，
      内核 panic 或 r8169 加载失败的时候 initrd sshd 也救不了你。

### initrd 救援 sshd 的 host key（**必须在 `nixos-rebuild boot` 之前**）

```bash
sudo mkdir -p /etc/secrets/initrd
sudo ssh-keygen -t ed25519 -N "" -f /etc/secrets/initrd/ssh_host_ed25519_key
```

不生成的话 `nixos-rebuild boot` 会在追加 initrd secrets 那步直接报错。
**不要复用系统的 host key** —— 它会明文躺在 sdd1 那个 vfat ESP 上。

```bash
# 瘦身，155G 里 /nix 占 126G
sudo nix-collect-garbage -d
sudo nix-store --optimise
df -hT /            # 看看降到多少
```

### ⚠️ 盘符会漂，一律用 UUID / by-id

2026-07-26 到 07-27 之间 tank 重启了两次，**`sda` 和 `sdd` 就对调了**
（系统盘 MZNTY256 从 sdd 变成 sda，14T WDC 从 sda 变成 sdd）。
本文档里所有磁盘一律用 UUID 或 by-id，**任何时候看到 `/dev/sdX` 都先 `lsblk` 核对一遍**。
Phase 2 要往系统盘写分区表，写错盘就是 14T 数据没了。

```
bcachefs fs   : UUID=2dc8bfeb-1f02-4c70-94dc-ecd07593e7f1   (Samsung 860 EVO 250G + WDC 14T)
ESP           : UUID=59E1-040D                              (系统盘 part1)
老 ext4 根     : UUID=d237c051-0e23-4021-a313-b1af5f6bbfbc   ← 救援用，别忘
系统盘 (by-id) : /dev/disk/by-id/ata-SAMSUNG_MZNTY256HDHP-000HW_S3CHNB0HA00646
```

---

## Phase 1 — 迁移（老 ext4 根全程保留，可回滚）

### 1. 拉分支 + 预热构建（不停机）

分支还没 push，先在 Mac 上 `git push -u origin tank-root-on-bcachefs`，然后在 tank 上：

```bash
cd ~/.config/nix-config
git stash          # tank 上 flake.lock 有本地改动
git fetch && git checkout tank-root-on-bcachefs
nix build --no-link .#nixosConfigurations.tank.config.system.build.toplevel
```

> 先 build 好，维护窗口里 `nixos-rebuild boot` 才能秒完。
> 注意 nix-daemon 的 TMPDIR 是 `/data/builds`，第 5 步 mv 之后就没了，所以构建必须在 mv 之前做完。

### 2. 在线全量 rsync（不停机，跑几十分钟）

rsync **之前**先把 `/home` 建成 subvolume（空目录，rsync 直接往里灌，零成本）：

```bash
sudo bcachefs subvolume create /data/home
```

根本身不做 subvolume。理由有两条，第二条才是决定性的：

1. bcachefs 大概率没有 `subvol=` 挂载选项，subvolume 挂不上当 `/`。
   证据：`/sys/fs/bcachefs/<uuid>/options/` 里没有 `subvol`，而这个列表是包含
   纯挂载期选项的（`fsck`/`norecovery`/`degraded`/`nochanges`/`noexcl` 都在）；
   模块里那几个 `subvol` 字符串是 BTF 类型名和 dirent 类型名，`subvol=%u` 紧挨着
   `bi_subvol=%llu`/`bi_parent_subvol=%llu`，属于 inode 调试打印而不是 `show_options`。
   （`bcachefs subvolume create --help` 里 "independently mountable" 的措辞有误导性。
   真要用的话先自己 `mount -o subvol=` 试一次，别信这段推断。）
2. 就算能挂也不该用：NixOS generations 已经是比快照更好的根回滚机制，
   /nix 那 126G 进快照纯属浪费，而且按数字 subvol ID 挂根在回滚后 ID 会变，很脆。

```bash
sudo rsync -aHAXx --numeric-ids --info=progress2 \
  --exclude=/data --exclude=/boot --exclude=/lost+found \
  --exclude='/tmp/*' --exclude=/var/lib/swapfile \
  / /data/
```

`-x` 保证不跨文件系统（/proc /sys /dev /run /efi 自动跳过）。
`--exclude=/data` 同时保护源的挂载点目录和目标已有的 `data/`（这一遍还没有）。
**这一遍不要加 `--delete`。**

### 3. ↓↓↓ 维护窗口开始 ↓↓↓ 停服务

```bash
sudo systemctl stop \
  postgresql mysql matrix-synapse murmur ollama filebrowser \
  nginx smbd nmbd nfs-server minecraft-server-* \
  libvirtd machines.target systemd-nspawn@debian-guest
```

**这里先别停 `nix-daemon`** —— 第 4 步的 `nixos-rebuild boot` 还要用它。
它的 `TMPDIR = /data/builds` 会在第 5 步被搬走，所以停它的时机是第 4 步之后、第 5 步之前。

（`services.postgresql.dataDir = /data/lib/postgresql`、`matrix-synapse.dataDir = /data/services/…`、
minecraft `dataDir = /data/srv/minecraft`、ollama `home = /data/lib/ollama` —— 全都在要动的目录下面）

sshd 不在停的列表里，全程不会断。`nixos-rebuild boot` 只写引导项不激活，也不会断。

### 4. 把 ESP 换到 /boot 再装引导器

```bash
sudo umount /efi
sudo mount /dev/disk/by-uuid/59E1-040D /boot
sudo nixos-rebuild boot --flake ~/.config/nix-config#tank
```

必须先 remount：新配置里 `efiSysMountPoint = /boot`，不 remount 的话 systemd-boot 会装进
ext4 根的 /boot 目录里，白装。

装完确认一下：

```bash
ls /boot/EFI/            # 应该有 systemd/ BOOT/ nixos/，以及残留的 NixOS-efi/（GRUB，留着当救援）
ls /boot/loader/entries/ # nixos-generation-*.conf
df -h /boot              # 1G ESP，configurationLimit=5，看看占了多少
```

⚠️ 如果这一步报 `failed to create initrd secrets`，是 Phase 0 那把 initrd host key
没生成。补上再重跑，**别带着这个错误往下走**——那样 initrd 里就没有救援 sshd。

### 4b. 现在才停 nix-daemon

```bash
sudo systemctl stop nix-daemon.socket nix-daemon.service
```

### 5. 重排 /data 布局

```bash
cd /data
sudo mkdir data
sudo mv builds lib nas rdma services srv test.txt data/
ls -la /data              # 现在应该是: bin data etc home lib64 lost+found nix opt root usr var
sudo bcachefs subvolume list /data | grep nas    # nas 是 subvolume(ID 2)，确认它跟着 mv 过去了
```

注意 `srv` 两边都有：源 `/srv` 是空目录（4K），第 2 步 rsync 把它合进了已有的
`/data/srv`（minecraft 存档），所以这里 mv 走的是完整的 minecraft 数据；
顶层 `srv` 会在第 6 步被重新建成空目录。

⚠️ 如果 `mv` 在 `nas` 上报错（subvolume 跨目录移动这一条没有实测过）：

```bash
sudo bcachefs subvolume create /data/data/nas
sudo rsync -aHAX --numeric-ids --info=progress2 /data/nas/ /data/data/nas/
sudo bcachefs subvolume delete /data/nas
```

### 6. 增量 rsync（这次带 --delete）

```bash
sudo rsync -aHAXx --numeric-ids --info=progress2 --delete \
  --exclude=/data --exclude=/boot --exclude=/lost+found \
  --exclude='/tmp/*' --exclude=/var/lib/swapfile \
  / /data/
```

`--delete` 配 `--exclude=/data`：被 exclude 的路径默认受保护，不会删掉刚搬进去的 `data/`。
**先不加 `--delete` 干跑一遍 `-n` 看看它想删什么**，确认里面没有 `data`：

```bash
sudo rsync -aHAXxn --delete --exclude=/data --exclude=/boot --exclude=/lost+found \
  --exclude='/tmp/*' --exclude=/var/lib/swapfile / /data/ | grep '^deleting' | head -50
```

### 7. 重启前检查

```bash
# 新 generation 的 store 路径确实到位了
readlink -f /data/nix/var/nix/profiles/system
ls -d $(readlink -f /data/nix/var/nix/profiles/system)   # 不能是 No such file
# 关键状态目录在
ls /data/data/lib/postgresql /data/data/services /data/data/nas /data/data/srv/minecraft
ls /data/var/lib/mysql /data/home/hank
```

顺手补一个 GRUB 救援启动项（`efibootmgr` 系统里没装）：

```bash
nix shell nixpkgs#efibootmgr -c sudo efibootmgr -v          # 先看老的 NixOS-efi 项还在不在
# 不在的话补一个，它会读 sdd2 ext4 上的 /boot/grub/grub.cfg 起老系统
nix shell nixpkgs#efibootmgr -c sudo efibootmgr -c \
  -d /dev/disk/by-id/ata-SAMSUNG_MZNTY256HDHP-000HW_S3CHNB0HA00646 -p 1 \
  -L "NixOS GRUB (rescue, ext4 root)" -l '\EFI\NixOS-efi\grubx64.efi'
```

```bash
sudo reboot
```

### 8. 首次启动验证

最容易出问题的地方：initrd 里两块盘（sdc + sda）要都被认出来 mount.bcachefs 才能挂上。

正常的话 tailscale 会回来，`ssh tank` 直接能上：

```bash
findmnt /                 # bcachefs, source 是两块盘 "/dev/sdX:/dev/sdY"（盘符别照字面对）
findmnt /boot             # vfat sdd1
bcachefs fs usage -h /
systemctl --failed
swapon --show             # zram
ls /data/nas /data/lib/postgresql
systemctl status postgresql mysql matrix-synapse smbd nfs-server
```

### 8b. 起不来的话：从 rpi4 跳进 initrd 抢救

`ssh tank` 走 tailscale，根挂不上的时候 tailscale 起不来，所以那条路是死的。
走 LAN：rpi4 就是 192.168.20.1，能独立访问。

```bash
ssh -J rpi4 -p 2222 root@192.168.20.50
```

进去之后（这是 initrd 里的 systemd，根还没挂）：

```bash
systemctl status sysroot.mount          # 看它到底卡在哪
journalctl -b | tail -50
bcachefs mount UUID=2dc8bfeb-1f02-4c70-94dc-ecd07593e7f1 /sysroot   # 手动试
lsblk -o NAME,SIZE,FSTYPE,UUID          # 两块盘都认出来了吗
systemctl start initrd-cleanup.service  # 挂上之后让它继续启动
```

实在救不回来，就在 initrd 里挂老 ext4 根，把 `fileSystems."/"` 改回去再重装引导器：

```bash
mkdir -p /mnt && mount /dev/disk/by-uuid/d237c051-0e23-4021-a313-b1af5f6bbfbc /mnt
# 或者直接重启后从固件菜单选 "NixOS GRUB (rescue, ext4 root)"
```

**initrd sshd 覆盖不了的情况**：内核 panic、r8169 没加载出来、systemd-boot 自己起不来。
这些还是只能到机器跟前。

### 回滚

老 ext4 根一个字节没动。固件启动菜单选 "NixOS GRUB (rescue)" 就回到迁移前的系统
（它的 /etc/fstab 仍然是 ext4 根 + /efi，只是 /efi 那块盘现在装的是 systemd-boot，无所谓）。

---

## Phase 2 — 跑稳 1～2 周之后，回收系统盘剩余空间

确认 bcachefs 根没出过问题、内核也升过一次之后再做。

⚠️ **这一步会往磁盘写分区表。全程用 by-id，写错盘 = 14T 数据没了。**
动手前先核对一遍：

```bash
SYS=/dev/disk/by-id/ata-SAMSUNG_MZNTY256HDHP-000HW_S3CHNB0HA00646
lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT $(readlink -f $SYS)   # 必须是 238.5G 那块，part1=/boot
```

```bash
# 1. 老 ext4 根不要了（part2）
sudo wipefs -a $SYS-part2

# 2. 重分区: part1 保持 1G ESP 不动，part2 → 16G swap, part3 → 剩余 ~220G
#    （sgdisk/partprobe 系统里没装，用 nix shell -c 一次性跑完，别开子 shell 再 sudo）
nix shell nixpkgs#gptfdisk nixpkgs#parted -c sudo sh -c "
  sgdisk -d 2 $SYS
  sgdisk -n 2:0:+16G -t 2:8200 -c 2:tankswap $SYS
  sgdisk -n 3:0:0    -t 3:8300 -c 3:bcachefs-ssd2 $SYS
  partprobe $SYS
"
sudo mkswap -L tankswap $SYS-part2

# 3. 剩余空间并进 ssd.fast
sudo bcachefs device add --label=ssd.fast / $SYS-part3
bcachefs fs usage -h /      # ssd.fast 应该从 231G 变成 ~450G
```

然后配置里把 swap 换回真分区：

```nix
  swapDevices = [{device = "/dev/disk/by-label/tankswap";}];
  zramSwap.enable = false;   # 或者两个都留，zram 优先级更高
```

---

## Phase 3 — IO 属性 & 快照（跟"分卷"无关，随时可做）

### 3a. per-inode IO 属性

命令是 **`bcachefs set-file-option`**（这个版本没有 `setattr`）。设在目录上会递归传播到
已有子文件、并被新文件继承；已有数据由 **reconcile 在后台按新选项重写**，不用手动 rewrite。

```bash
# /nix 钉在 SSD 上（fs 默认 background_target=hdd.14t，126G store 会被搬到机械盘）
sudo bcachefs set-file-option --background_target=ssd.fast --promote_target=ssd.fast /nix

# /home 双副本（fs 默认 data_replicas=1；/home 是唯一没有别处备份的东西）
sudo bcachefs set-file-option --data_replicas=2 /home

# 影音已经压过了，别再烧 CPU
sudo bcachefs set-file-option --compression=none --background_compression=none /data/nas

# nix build 的 TMPDIR，纯临时数据
sudo bcachefs set-file-option --compression=none /data/builds

# 进度
bcachefs fs usage -h /        # 看 "Pending reconcile"
bcachefs reconcile status
```

⚠️ `--nocow` 对 VM 镜像/数据库能减少写放大，但它会同时关掉校验和与压缩，而且和多副本
交互比较微妙。想用先只在 libvirt 镜像目录上试。

### 3b. subvolume（只为快照，不为别的）

值得建的（都在同一个 fs 上，停服务 → `mv` 一下，秒完）：

```bash
# 模板：以 postgres 为例
sudo systemctl stop postgresql
sudo mv /data/lib/postgresql /data/lib/postgresql.old
sudo bcachefs subvolume create /data/lib/postgresql
sudo mv /data/lib/postgresql.old/* /data/lib/postgresql/
sudo rmdir /data/lib/postgresql.old
sudo systemctl start postgresql
```

- `/data/srv/minecraft`  ← 最值，世界存档
- `/data/lib/postgresql`
- `/data/services/matrix-synapse`
- `/var/lib/mysql`
- `/data/nas` 已经是 subvolume 了 ✓
- `/home` Phase 1 里已经建好 ✓

**明确不要建的**：`/nix`（126G，generations 已经管回滚）、`/var/log`、`/data/builds`。

拍快照：

```bash
sudo bcachefs subvolume snapshot -r /data/srv/minecraft /data/snapshots/minecraft-20260726
```

`-r` = 只读，冻结的时间点副本。COW，初始不占额外空间。fs 有 `auto_snapshot_deletion`
选项管死快照回收，但**定期清理还是得自己写个 systemd timer**，别让快照无限堆积。

---

## 验证状态（2026-07-26）

- `nixosConfigurations.tank.config.system.build.toplevel` 求值通过；实测
  `grub=false / systemd-boot=true / efiSysMountPoint=/boot / 无 /data 挂载点 /
  initrd 里有 bcachefs 内核模块和 mount.bcachefs / autoScrub.fileSystems=["/"]`。
- `boot.initrd.systemd.enable = true` 在 26.05 里**已经是默认值**，这行是 no-op，
  留着只是防默认翻回去（tank 现在跑的就已经是 systemd initrd）。
- initrd 救援 sshd 实测求值结果：`boot.initrd.secrets` 里确实是
  `/etc/secrets/initrd/ssh_host_ed25519_key`（走 ESP 追加，不进 nix store）、
  `authorizedKeys` 8 把（默认值是空的，必须显式给，见下）、
  `systemd.network` 里 enp5s0 = 192.168.20.50/24 gw 192.168.20.1、
  `r8169` 在 `availableKernelModules` 里、`af_packet` 在 `initrd.kernelModules` 里。
- 注意本仓库的 SSH key 是通过 `/etc/ssh/authorized_keys.d/master` 发的，
  `users.users.root.openssh.authorizedKeys.keys` 是**空的** —— 而那正是
  `boot.initrd.network.ssh.authorizedKeys` 的默认值。所以 key 列表抽到了
  `nixos/modules/ssh/keys.nix`，两边共用。
- **没有在 Linux 上真正构建过。** 在 Mac 上跑 `just check` 没意义：`nix flake check`
  会打印 "omitted these incompatible systems: aarch64-linux, x86_64-darwin,
  x86_64-linux"，只跑 `checks.aarch64-darwin.*`，压根没碰 tank；而且它会因为 macOS
  大小写不敏感 store 的 case hack 挂掉（`make-initrd-ng` 找
  `ncurses/share/terminfo/l/linux`，本地 store 里实际叫 `l~nix~case~hack~1`）——
  失败的是 aarch64-linux 那台的 initrd，跟本改动无关，main 上同样挂。
  → 真正的验证是 Phase 1 第 1 步在 tank 上 `nix build`，**别跳过**。

---

## 后续建议

`boot.kernelPackages = pkgs.linuxPackages_latest`（2026-07-26 实测 7.1.1）。bcachefs 已经是
树外模块（`updates/src/fs/bcachefs/bcachefs.ko`，tools 1.38.6）。以前它编不出来只是 /data
挂不上（还有 `nofail` 兜着），根搬过去之后就是整机起不来。建议钉一个具体内核版本，
升级前先确认 `bcachefs-tools` 的模块能跟着编出来。
