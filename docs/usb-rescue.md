# x86_64 救援U盘

`nixosConfigurations.x86_64-rescue` 提供用于 M16、9950x 和其他 x86_64
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

9950x 的网线经 r5sjp 的 `br-lan` 桥接到路由器，救援系统从路由器获取
`10.1.2.0/24` 网段地址。r5sjp 的局域网地址为 `10.1.2.107`。需要从
Tailscale 网络进入该局域网时，可以使用：

```sh
ssh -J hank@r5sjp root@<救援系统的局域网地址>
```

控制台提供 `ip -brief address` 和 `nmcli device status` 查询网络。
救援系统每次启动生成 SSH 主机密钥，重新连接时应核实主机密钥变化。

## 构建和写入

在 x86_64 Linux 构建机执行：

```sh
nix build .#nixosConfigurations.x86_64-rescue.config.system.build.isoImage
```

输出位于 `result/iso/`。`nixos/installers/grub-iso.nix` 使用 NixOS 的
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

## 本地系统启动

9950x 的本地安装使用 GRUB。Windows 从 GRUB 菜单进入，Windows Boot
Manager 的固件启动项在确认目标 EFI 分区后处理。M16 的具体配置和已验证
行为见 [M16 安装记录](m16-installation.md)。

U盘适用于支持 Linux 驱动的 x86_64 机器，UEFI 启动需要关闭 Secure Boot。

## 当前介质与验证

2026-10-04 已写入 M16 上的 ELECOM MF-DAU3，序列号
`07083421BA974624`，设备容量为 31,042,043,904 字节。
磁盘镜像大小为 2,415,919,104 字节，SHA-256 为：

```text
2a1df2ff43a04a4fa93b682b2480ae4070fdb15fe2302167431ad3eb223d0f25
```

第三分区内的救援数据 ISO 大小为 1,516,478,464 字节，SHA-256 为：

```text
27ac7ebf30cf770d7028e6a6ff1154bd253ebbb7e8bfc4b0250f53e5f62051ad
```

写入后完整比较磁盘镜像覆盖范围，通过后将备份 GPT 移到设备末尾。调整
后的 GPT 和 FAT32 检查通过，EFI 分区与镜像对应区域、救援分区与完整
ISO 均逐字节一致。EFI 分区 UUID 为 `9CC9-7992`，PARTUUID 为
`89a6b4ed-7286-4a3a-a33c-6f244d79ad71`。

已在 M16 的 QEMU/KVM 中通过 UEFI、BIOS 启动最终磁盘镜像，并将实际
U盘以只读方式连接给虚拟机完成 BIOS 启动。三个测试均通过 `root`、
`nixos` 公钥登录、sudo、有线 DHCP、DNS、内存根目录、Wi-Fi 配置加载、
SSH 认证设置和维护工具检查，救援系统没有失败的 systemd 服务。Wi-Fi
凭据与原有U盘一致。

M16 的固件启动列表仅保留两个入口，`BootOrder` 为 `0000,0001`：

- `Boot0000`：SSD 上的 GRUB，默认启动本地 NixOS。
- `Boot0001`：`NixOS Rescue USB`，通过第一分区的 PARTUUID 定位
  `\EFI\BOOT\BOOTX64.EFI`，入口适用于不同的 USB 接口。

2026-10-04 已在 M16 实机通过 `Boot0001` 启动U盘，确认根目录位于内存、
SSD 根分区未挂载、Wi-Fi 获取 `10.1.2.137`、DNS 正常，`root` 和 `nixos`
均可使用公钥登录，维护工具及 systemd 服务检查通过。随后通过 `Boot0000`
返回 SSD，启动顺序仍为 `0000,0001`，SSH、Tailscale 和数据库服务正常。
SSD 启动变量和 EFI 引导程序与维护前的备份一致。

启动项通过 SSD GRUB 的一次性入口进入 UEFI Shell 后完成整理。维护结束后
已清除临时入口及 EFI 维护文件。固件变量空间仍触及 Linux 写入保护阈值；
后续调整固件启动项时应检查写入结果。U盘保留标准可移动介质引导路径，
在其他机器上通过该机器的固件启动菜单选择U盘。

配置通过救援 ISO 的完整构建和磁盘镜像生成工具的实际运行；生成工具
通过 ShellCheck。Mac 与 M16 计算出的 ISO derivation 一致，Nix 文件
通过 Alejandra 格式检查，救援数据分区中的全部文件与源 ISO 内容一致。
镜像、原有介质备份和测试记录位于 Mac 仓库的 `.work/usb-rescue/`，
M16 的对应目录为 `/home/hank/.work/usb-rescue/`；两个目录均限制访问权限。

2026-10-04 已在 MSI B850 GAMING PLUS WIFI（MS-7E56）的 9950x 实机上
通过 UEFI 启动。Realtek RTL8126 有线网卡由 r8169 驱动，经 r5sjp 桥接
取得 `10.1.2.194`。`root`、`nixos` 公钥登录、sudo、DNS、内存根目录、
Wi-Fi 配置和维护工具检查均通过，救援系统没有失败的 systemd 服务。

## 9950x 本地系统

主机配置为 `nixosConfigurations.9950x-native`，用户环境为
`homeConfigurations."linwhite@9950x-native"`。系统提供 GNOME、RTX 5070
的 NVIDIA 开放内核驱动、AMD CPU 微码、有线 DHCP、Wi-Fi 和 SSH。
管理名称为 `9950x-native.inner.imdomestic.com`，局域网名称为
`9950x-native.local`。本地登录密码使用 M16 上 linwhite 账户的现有密码。

安装空间从 D 盘划分，总计 750 GiB。目标硬盘为 Samsung 970 EVO Plus
2 TB，序列号 `S4J4NX0R400720Y`。分区布局如下：

| 分区 | 容量 | 文件系统 | 用途 |
| --- | --- | --- | --- |
| 第一分区 | 约 181 GiB | NTFS | D 盘，UUID `7CBC355ABC35105E` |
| 第二分区 | 约 932 GiB | NTFS | 现有数据分区，UUID `20FCF685ED4F0BEA` |
| 第三分区 | 2 GiB | FAT32，`BOOT9950X` | `/boot`，保存 GRUB、内核和 initrd |
| 第四分区 | 748 GiB | ext4，`NIXOS9950X` | NixOS 根目录 |

D 盘缩容前已完成完整 NTFS 镜像备份、压缩检查、恢复格式检查，以及
传输前后 SHA-256 比较。备份位于 M16 的
`/home/hank/.work/9950x-install/d-drive.ntfs.zst`，约 83 GiB。
NTFS 镜像 SHA-256 为
`91ee001049996ce6fcbab3ce04123f67b92b99a311d331bf24ff210bca4a9097`。
缩容后 NTFS 检查通过，D 盘根目录文件列表一致，第一分区的起始扇区和
标识保持一致，第二分区完整保持原有边界和标识。另外两块硬盘的 GPT
与操作前备份逐字节一致。

GRUB 安装在新建 EFI 分区的 `EFI/BOOT/BOOTX64.EFI`，默认启动 NixOS，
等待时间为 5 秒。Windows 菜单通过 UUID `8C8A-383D` 定位 Predator
硬盘上的原有 EFI 分区，加载 `EFI/Microsoft/Boot/windows.efi`。
该分区挂载到 `/windows-efi`。原 `EFI/Boot/bootx64.efi` 与 Windows
引导程序逐字节一致，保存为同目录下的 `windows.efi`。
`9950x-boot-entries.service` 在启动时
维护 Windows 引导程序文件名，并备份、删除指向该分区的 Windows Boot
Manager 固件启动项，同时清理 MSI 自动生成的光驱、通用可移动设备和
网络设备 BBS 入口。

linwhite 使用本机独立生成的 Ed25519 密钥，Home Manager 的 sops-nix
通过对应的 age 接收者解密 OpenCode 凭据。系统与用户环境分别构建和
部署，后续用户环境更新执行 `just hm 9950x-native linwhite`。

2026-10-04 已完成安装，并在U盘保持连接时验证从本地 SSD 重启。
固件只保留 `Boot0002`（`GRUB NixOS 9950x`）与 `Boot0001`（救援U盘），
`BootOrder` 为 `0002,0001`，`BootCurrent` 为 `0002`。
根目录使用 ext4 卷标 `NIXOS9950X`，安装后可用空间约 700 GiB。
NVMe 设备编号在两次启动间发生变化，挂载和引导均通过卷标或 UUID 定位。

有线地址为 `10.1.2.194`，Tailscale 地址为 `100.64.0.44`。已验证局域网
SSH、经 r5sjp 跳转的 SSH、Tailscale SSH、linwhite 的 sudo、DNS、
Home Manager 激活、凭据解密和终端工具。GNOME 的 Wayland 登录会话
正常，NVIDIA 驱动 `595.71.05` 识别 RTX 5070 与 12,227 MiB 显存，
系统和用户均没有失败的 systemd 服务。Windows EFI 文件和 GRUB 菜单
通过检查；本次未实际启动 Windows。

全部 20 个 NixOS 主机配置通过求值，新主机的系统和用户环境完成实际
构建，新增 Nix 文件通过 Alejandra 格式检查。分区、EFI 和验证记录位于
Mac 仓库的 `.work/9950x-install/`，以及本机
`/root/.work/9950x-install/`，目录均限制访问权限。

本机配置仓库位于 `/home/linwhite/.config/nix-config`。已同步锁定源文件，
并在本机求值系统和 linwhite 用户环境，两者的输出路径均与已安装版本
一致。安装结束后再次计算U盘救援数据的 SHA-256，与原有镜像一致。
