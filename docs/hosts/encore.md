# encore

ROG Zephyrus M16 GU603ZM：i7-12700H、RTX 3060 Laptop（6 GiB）、Micron 3400 512 GB NVMe。
主机定义在 `hosts/encore/`，作为 GPU 服务器运行，合盖和空闲都不休眠；网络走 Wi-Fi `wlo1`。

| 名称 | 地址 |
| --- | --- |
| NixOS（Tailscale 节点 `encore`） | `encore.inner.imdomestic.com`，`100.64.0.43`；局域网 `encore.local` |
| 同机 Windows（节点 `m16`） | `m16.inner.imdomestic.com`，`100.64.0.28` |

## 磁盘与启动

Windows 与 NixOS 同盘。NixOS 占 350 GiB（2026-10-03 扩容到这个大小）：

| 分区 | 容量 | 文件系统 | 用途 |
| --- | --- | --- | --- |
| `nvme0n1p1` | 300 MiB | FAT32，UUID `6219-21FA` | 原 EFI 分区，挂载到 `/efi` |
| `nvme0n1p2` | 16 MiB | Microsoft Reserved | Windows 保留分区 |
| `nvme0n1p3` | 约 126.63 GiB | NTFS | Windows |
| `nvme0n1p4` | 2 GiB | FAT32，`ENCOREBOOT`，GPT 类型为 XBOOTLDR | `/boot`，内核与引导项 |
| `nvme0n1p5` | 348 GiB | ext4，`ENCOREROOT` | NixOS 根 |

引导是 systemd-boot（2026-11-10 从 GRUB 切换，理由见
`docs/decisions.md#encore-systemd-boot`）。华硕固件会为 `bootmgfw.efi` 自动重建
Windows Boot Manager 并抢默认，所以 Windows 引导程序改名为 `windows.efi`；
`encore-boot-entries.service` 每次启动时同步它、生成 systemd-boot 的 Windows 条目，
备份并删除固件自动加的 Windows Boot Manager、光驱、可移动设备和网络 BBS 入口。
固件的 `Boot0000` 指向 `\EFI\BOOT\BOOTX64.EFI`，激活时会把最新的 systemd-boot 放到这里。

`Boot0001` 是救援 U 盘（ELECOM MF-DAU3，按第一分区 PARTUUID 定位，换 USB 口也能用），
开机按住 Esc 可选。U 盘的制作和使用见 [救援 U 盘](../runbooks/usb-rescue.md)。

改 NTFS 分区前：在 Windows 里 `powercfg /h off` 并完全关机，再从 U 盘确认 NTFS 可读写；
NTFS-3G 报元数据还在 Windows 缓存里时，回 Windows 完整关机后再试。

## 重装

1. 从救援 U 盘启动（自带 Wi-Fi 凭据，`ssh root@nixos-rescue.local`）。
2. `ENCOREROOT` 挂到 `/mnt`，`ENCOREBOOT` 挂到 `/mnt/boot`，原 EFI 分区挂到 `/mnt/efi`。
3. 把 U 盘的 `/iso/installer-network.env` 以 root、`0600` 写到
   `/mnt/var/lib/NetworkManager/encore-wifi.env`；NetworkManager 用它生成持久 Wi-Fi 连接。
4. 本地登录密码用 `hashedPasswordFile`，散列放在 `/var/lib/user-passwords/{linwhite,hank}`
   （仅 root 可读），安装前建好，不进仓库。
5. 在 tank 构建系统，`nix copy` 到 `/mnt` 的 store，再
   `nixos-install --root /mnt --system <store-path> --no-root-passwd --no-channel-copy`。
6. Tailscale 状态在 `/var/lib/tailscale`；安装时注册过的话首次启动直接连上。

## 散热 {#cooling}

配置在 `hosts/encore/cooling.nix`。

`services.asusd` 管两只风扇，quiet / balanced / performance 用同一条曲线，由硬件控制器执行：

| 温度 | 30°C | 40°C | 50°C | 60°C | 65°C | 70°C 及以上 |
| --- | --- | --- | --- | --- | --- | --- |
| 风扇 PWM | 约 35% | 50% | 65% | 80% | 90% | 100% |

`services.throttled` 每 5 秒重新应用功耗与温度限制，并处理电源切换：

| 电源 | PL1 | PL2 | 温度目标 |
| --- | --- | --- | --- |
| 接电 | 45 W | 55 W | 80°C |
| 电池 | 25 W | 35 W | 80°C |

系统电源档位和 CPU EPP 由 power-profiles-daemon 管。asus-shutdown 的停止超时是 45 秒，
超时后结束辅助进程，保证 asusd 能重启。

2026-10-17 清灰换硅脂后，接电、balanced、45 W 下 `stress-ng --cpu-method matrixprod --verify`：
4 个工作进程 180 秒 CPU 平均 75.4°C / 最高 80°C；20 个进程 300 秒平均 68.7°C / 最高 70°C；
没有新增温度限频计数。CPU 风扇约 6400 RPM，GPU 风扇约 4800 RPM。

检查（在 encore 上）：

```sh
systemctl status asusd throttled
asusctl fan-curve --get-enabled
powerprofilesctl get
cat /sys/class/powercap/intel-rapl:0/constraint_0_power_limit_uw   # 接电时 45000000
cat /sys/class/powercap/intel-rapl:0/constraint_1_power_limit_uw   # 接电时 55000000
journalctl -b -u throttled
```

## 旧 Minecraft 服的数据 {#minecraft-data}

encore 上原来的 Velocity / lobby / bingo / speedrun / GTL 已全部停掉，服务定义也删了。
数据还在：

- 世界、玩家数据、管理员与封禁名单：`/var/lib/minecraft`（属主 `minecraft`）。
- PostgreSQL 16 的 `minecraft`、`luckperms` 库，MariaDB 的 `minecraft` 库（CMI 用），
  仍由 `hosts/encore/retained-services.nix` 声明；代理的 LuckPerms 是 H2 文件，
  SkinsRestorer 是文件存储。
- 凭据：`/var/lib/minecraft-secrets`（`runtime.env`、`database.json`、`forwarding.secret`），
  不进 Git，需要单独备份。

运营网络的去向见 [Minecraft 网络](../minecraft-network-todo.md)。
