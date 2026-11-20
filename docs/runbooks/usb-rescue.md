# x86_64 救援U盘

`nixosConfigurations.x86_64-rescue` 提供用于 encore、seraph 和其他 x86_64
机器的 NixOS 救援与安装系统。UEFI 和传统 BIOS 均通过 GRUB 启动。
系统包含通用硬件驱动及固件，根目录位于内存，安装介质以只读方式挂载。
本地磁盘的分区、文件系统和固件启动项由维护操作显式管理。

## 网络与登录

有线网卡通过 NetworkManager 自动获取 DHCP 地址。配置通过网卡类型匹配，
适用于不同的接口名称和 MAC 地址。现有 Wi-Fi 配置随U盘保留，合上笔记本
盖子后救援系统继续运行。

`root` 和 `nixos` 接受 linwhite 的 SSH 公钥，`nixos` 可以使用免密码 sudo。
SSH 关闭密码认证。局域网主机名为 `nixos-rescue.local`：

```sh
ssh root@nixos-rescue.local
```

seraph 的网线经 gizmo 的 `br-lan` 桥接到路由器，救援系统从路由器获取
`10.1.2.0/24` 网段地址。gizmo 的局域网地址为 `10.1.2.107`。需要从
Tailscale 网络进入该局域网时，可以使用：

```sh
ssh -J hank@gizmo root@<救援系统的局域网地址>
```

控制台提供 `ip -brief address` 和 `nmcli device status` 查询网络。
救援系统每次启动生成 SSH 主机密钥，重新连接时应核实主机密钥变化。

## 构建和写入

在 x86_64 Linux 构建机执行：

```sh
nix build .#nixosConfigurations.x86_64-rescue.config.system.build.isoImage
```

输出位于 `result/iso/`。`system/installers/grub-iso.nix` 使用 NixOS 的
UEFI GRUB 镜像及 `grub-mkrescue` 生成 ISO，系统内容和启动菜单均保存在
ISO 中。

Wi-Fi 凭据保存在受保护并被 Git 忽略的工作目录，文件名为
`installer-network.env`，提供 `INSTALLER_WIFI_SSID` 和
`INSTALLER_WIFI_PASSWORD`。制作最终镜像时执行：

```sh
xorriso -indev base.iso -outdev nixos-rescue.iso \
  -map installer-network.env /installer-network.env \
  -boot_image any replay
```

NetworkManager 从 `/iso/installer-network.env` 读取凭据。最终镜像和U盘
包含这些凭据，需要与原有安装介质一样妥善保管。

构建磁盘镜像生成工具，再将包含凭据的 ISO 放入标准 GPT 磁盘镜像：

```sh
nix build .#nixosConfigurations.x86_64-rescue.config.system.build.usbImageBuilder \
  --out-link usb-image-builder
sudo ./usb-image-builder/bin/build-rescue-usb-image \
  nixos-rescue.iso .work/usb-image
```

输出为 `.work/usb-image/rescue-usb.img`。工具将救援文件生成为纯 ISO9660
数据镜像 `rescue-data.iso`，并将其写入第三分区。工具需要 Linux 的 loop
设备及挂载权限，输出目录应位于受保护、被 Git 忽略的工作目录中。
磁盘布局为：

| 分区 | 容量 | 格式 | 用途 |
| --- | --- | --- | --- |
| 第一分区 | 512 MiB | FAT32，EFI System Partition | `EFI/BOOT/BOOTX64.EFI` 和 GRUB 文件 |
| 第二分区 | 2 MiB | BIOS Boot Partition | GRUB BIOS 引导程序 |
| 第三分区 | 随 ISO 大小确定 | ISO9660，`NIXOS_RESCUE` | 完整救援系统和 Wi-Fi 配置 |

UEFI 和 BIOS 的 GRUB 均从第三分区读取系统启动菜单。UEFI 使用标准
可移动介质路径；在其他机器上启动无需提前登记固件启动项。

写入前通过设备型号、序列号、USB 总线及所有分区的挂载状态确认目标，
并备份现有安装镜像。将 `rescue-usb.img` 写入整个U盘，刷新缓存并逐字节
比较镜像覆盖范围，随后使用 `sgdisk --move-second-header` 将备份 GPT
移到实际设备末尾。重新读取分区表，检查 GPT 和 FAT32，再分别比较第一
分区与磁盘镜像、第三分区与 `rescue-data.iso`，确认文件系统内容一致。调整 GPT 后的整个
设备散列与原始磁盘镜像不同。

启动测试使用 QEMU/KVM，将镜像或实际U盘作为只读 USB 磁盘，分别检查
UEFI、BIOS、SSH 公钥登录、有线 DHCP、DNS、Wi-Fi 配置及维护工具。

## 当前介质

encore 上插着的 ELECOM MF-DAU3（序列号 `07083421BA974624`）是 2026-10-04 写入的版本，
EFI 分区 UUID `9CC9-7992`、PARTUUID `89a6b4ed-7286-4a3a-a33c-6f244d79ad71`，
encore 固件的 `Boot0001` 按这个 PARTUUID 找它。磁盘镜像 SHA-256 为
`2a1df2ff43a04a4fa93b682b2480ae4070fdb15fe2302167431ad3eb223d0f25`，
第三分区的救援数据 ISO 为
`27ac7ebf30cf770d7028e6a6ff1154bd253ebbb7e8bfc4b0250f53e5f62051ad`。
镜像和旧介质备份在 Mac 仓库的 `.work/usb-rescue/`（不进 Git）。

U 盘适用于 Linux 驱动支持的 x86_64 机器；UEFI 启动需要关闭 Secure Boot。
已在 encore（UEFI，实机）和 seraph（UEFI，实机）上启动过。各机器的分区与启动项见
[encore](../hosts/encore.md)、[seraph](../hosts/seraph.md)。
