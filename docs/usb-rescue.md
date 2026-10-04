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
UEFI GRUB 镜像及 `grub-mkrescue` 生成 BIOS 引导程序；EFI 文件系统作为
独立 GPT 分区附加到镜像，支持直接写入 USB 磁盘后启动。

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

写入前通过设备型号、序列号、USB 总线及挂载状态确认目标，并备份现有
安装镜像。写入后对镜像覆盖的全部字节进行 SHA-256 校验。启动测试使用
QEMU/KVM，将镜像或实际U盘作为只读 USB 磁盘，分别检查 UEFI、BIOS、
SSH 公钥登录、有线 DHCP、DNS、Wi-Fi 配置及维护工具。

## 本地系统启动

9950x 的本地安装使用 GRUB。Windows 从 GRUB 菜单进入，Windows Boot
Manager 的固件启动项在确认目标 EFI 分区后处理。M16 的具体配置和已验证
行为见 [M16 安装记录](m16-installation.md)。

U盘适用于支持 Linux 驱动的 x86_64 机器，UEFI 启动需要关闭 Secure Boot。

## 当前介质与验证

2026-10-04 已写入 M16 上的 ELECOM MF-DAU3，序列号
`07083421BA974624`，设备容量为 31,042,043,904 字节。
镜像覆盖 1,519,779,840 字节，完整读取内容与最终镜像逐字节一致，SHA-256 为：

```text
4764a10c1e9ede89b6ddbf8e5a45ce457c5d2663ebabefa166acb3e35ce17cd0
```

已在 M16 的 QEMU/KVM 中分别通过 UEFI 和 BIOS 启动最终镜像及实际U盘，
共完成四次启动测试。实际U盘以只读磁盘连接给虚拟机，两种启动方式均通过
`root`、`nixos` 公钥登录、sudo、有线 DHCP、DNS、内存根目录、Wi-Fi
配置加载、SSH 认证设置和维护工具检查，救援系统没有失败的 systemd 服务。
Wi-Fi 凭据与原有U盘一致。测试完成后虚拟机正常关闭，M16 继续运行 SSD
上的系统，SSH、NetworkManager 和 Tailscale 正常。

M16 的固件启动列表仅保留两个入口，`BootOrder` 为 `0000,0001`：

- `Boot0000`：SSD 上的 GRUB，默认启动本地 NixOS。
- `Boot0001`：`NixOS Rescue USB`，指向当前U盘第二分区的
  `\EFI\BOOT\BOOTX64.EFI`。该入口包含当前 USB 接口的设备路径。

2026-10-04 已在 M16 实机通过 `Boot0001` 启动U盘，确认根目录位于内存、
SSD 根分区未挂载、Wi-Fi 获取 `10.1.2.137`、DNS 正常，`root` 和 `nixos`
均可使用公钥登录，维护工具及 systemd 服务检查通过。随后通过 `Boot0000`
返回 SSD，启动顺序仍为 `0000,0001`，SSH、Tailscale 和数据库服务正常。
SSD 启动变量和 EFI 引导程序与维护前的备份一致。

启动项通过 SSD GRUB 的一次性入口进入 UEFI Shell 后完成整理。维护结束后
已清除临时入口及 EFI 维护文件。固件变量空间仍触及 Linux 写入保护阈值；
后续调整固件启动项时应检查写入结果。U盘保留标准可移动介质引导路径，
在其他机器上通过该机器的固件启动菜单选择U盘。

配置通过 `nix flake check --no-build` 和救援 ISO 的完整构建。
Mac 与 M16 计算出的 ISO derivation 一致。
镜像、原有介质备份和测试记录位于 Mac 仓库的 `.work/usb-rescue/`，
M16 的对应目录为 `/home/hank/.work/usb-rescue/`；两个目录均限制访问权限。

U盘目前连接在 M16 上。9950x 的本地系统安装和 Windows Boot Manager
启动项处理，需要将U盘移到 9950x 并从救援系统启动后进行。
