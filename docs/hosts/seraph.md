# seraph

MSI B850 GAMING PLUS WIFI（MS-7E56）、AMD Granite Ridge、RTX 5070（12 GiB）。
linwhite 的机器，`nixosConfigurations.seraph`，只通过 SSH 使用。

| 名称 | 地址 |
| --- | --- |
| NixOS | `seraph.inner.imdomestic.com`，`100.64.0.44`；局域网 `seraph.local`，有线 `10.1.2.194` |
| 同机 Windows | `9950x.inner.imdomestic.com`，`100.64.0.17`；WSL 配置是 `nixosConfigurations.9950x` |

网线经 gizmo 的 `br-lan` 桥接到路由器（`10.1.2.0/24`，gizmo 是 `10.1.2.107`）。
从 tailnet 进这个局域网：`ssh -J hank@gizmo <user>@<局域网地址>`。

## SSH 计算节点

`hosts/seraph/compute.nix` 把它设成计算节点：默认目标 `multi-user.target`，GNOME、GDM、
Xserver、音频、打印和蓝牙都关掉。两张显卡的 Linux 显示功能都停用：

```text
initcall_blacklist=sysfb_init
module_blacklist=amdgpu,radeon,nvidia_drm,nvidia_modeset
```

核显在 PCI `0000:10:00.0`，5070 在 `0000:01:00.0`。CUDA 由 `nvidia`、`nvidia_uvm`、开放内核
模块、持久化服务和容器 CDI 提供；`hardware.graphics.enable` 只为 `/run/opengl-driver`
运行库目录。UEFI 和引导程序自己的画面不受这些参数影响。

验收时不能只看显存 Used：还要看 DRM 设备归属、进程打开的设备句柄和内核模块。
空闲时 `nvidia-smi` 报 Total 12227 MiB、Reserved 476 MiB（驱动保留，不是图形进程）、
Used 0 MiB。物理显示器在 Linux 下仍亮着，接口断开和显示器待机没有验收过。

上面跑的推理服务见 [Bonsai](../services/bonsai.md)、[SillyTavern](../services/sillytavern.md)、
[Lumiverse](../services/lumiverse.md)，SMB 共享见 [linwhite 的 SMB](../services/linwhite-smb.md)。

## 磁盘与启动

NixOS 装在 Samsung 970 EVO Plus 2 TB 上，从原 D 盘划出 750 GiB：

| 分区 | 容量 | 文件系统 | 用途 |
| --- | --- | --- | --- |
| 1 | 约 181 GiB | NTFS，UUID `7CBC355ABC35105E` | D 盘 |
| 2 | 约 932 GiB | NTFS，UUID `20FCF685ED4F0BEA` | 数据分区 |
| 3 | 2 GiB | FAT32，`BOOTMS7E56`，UUID `8DC1-C232` | `/boot`（Linux ESP） |
| 4 | 748 GiB | ext4，`NIXOSMS7E56` | NixOS 根 |

Windows 的 ESP 在另一块（Predator）NVMe 上，UUID `8C8A-383D`，挂载到 `/windows-efi`。
NVMe 编号在两次启动间会变，挂载和引导一律用 UUID。

引导是 systemd-boot，准备切到 Lanzaboote 安全启动；Windows 的整个 `EFI/Microsoft`
目录同步到 Linux ESP，`seraph-boot-entries.service` 维护 `windows.efi` 改名并清理固件
自动生成的启动项。步骤和恢复见 [安全启动 runbook](../runbooks/seraph-secure-boot.md)。
救援 U 盘在这台机器上也能 UEFI 启动（RTL8126 有线网卡由 r8169 驱动）。
