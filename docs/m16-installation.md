# m16 安装介质

`nixosConfigurations.m16-installer` 提供 x86_64 NixOS 安装系统，支持 UEFI 和 USB 启动。系统通过 NetworkManager 自动连接 Wi-Fi，启动 SSH，并通过 Avahi 发布 `m16-installer.local`。`root` 和 `nixos` 接受 linwhite 的 SSH 公钥。

系统启动后可从持有对应私钥的 Mac 连接：

```sh
ssh root@m16-installer.local
```

控制台可以通过 `ip -brief address` 查询地址，通过 `nmcli device status` 检查网络。安装环境关闭自动休眠，合上盖子后保持运行。

## 构建与写入

在 x86_64 Linux 构建机运行：

```sh
nix build .#nixosConfigurations.m16-installer.config.system.build.isoImage
```

输出位于 `result/iso/`。Wi-Fi 凭据保存在本机受保护且被 Git 忽略的工作目录，文件名为 `installer-network.env`，提供 `INSTALLER_WIFI_SSID` 和 `INSTALLER_WIFI_PASSWORD` 两个变量。

将镜像下载到本机后，使用 xorriso 写入凭据并保留启动信息：

```sh
xorriso -indev base.iso -outdev m16-installer.iso \
  -map installer-network.env /installer-network.env \
  -boot_image any replay
```

安装系统使用 `networking.networkmanager.ensureProfiles`，从 `/iso/installer-network.env` 读取凭据。凭据仅保存在本机和安装介质中。基础镜像可以在构建机生成，凭据写入和最终镜像测试在本机进行。

将最终镜像作为 USB 磁盘写入，写入前核对设备型号、容量和外置 USB 属性，写入后读取镜像对应的全部字节进行 SHA-256 校验。镜像应通过真实 UEFI 启动、SSH 公钥登录和 NetworkManager 配置加载测试。

## 安装系统与用户环境

主机定义位于 `nixos/hosts/m16/`，角色为带 GNOME 桌面的 GPU 服务器。Intel 核显负责桌面，RTX 3060 提供计算能力，Podman 可以使用 NVIDIA CDI。合盖和空闲均保持运行。局域网地址为 `m16.local`，服务器管理地址为 `m16.inner.imdomestic.com`。

Windows 的 Tailscale 节点名称为 `m16-windows`，地址为 `100.64.0.28`；NixOS 使用独立的 `m16` 节点身份，地址为 `100.64.0.43`。NixOS 的节点状态保存在 `/var/lib/tailscale`。

用户环境保持独立：`homeConfigurations."hank@m16"` 使用 b650 的个人配置、开发工具和 GNOME 模块；`homeConfigurations."linwhite@m16"` 与 m1pro 共用个人配置、开发工具和图形工具配置，软件按各自平台构建。

### 磁盘与启动

安装目标为 Micron 3400 512 GB NVMe。保留 Windows 分区、Microsoft 保留分区和原有 EFI 分区。先在 Windows 管理员终端运行 `powercfg /h off`，保存文件后执行 `shutdown /s /t 0`，从 USB 启动并确认 NTFS 可以正常读写。

如果 NTFS-3G 报告元数据仍保留在 Windows 缓存中，需要进入 Windows 完成恢复和完整关机，直到读写探测通过，才可以调整分区。

NixOS 分配容量为 350 GiB，包含 2 GiB 的 FAT32 启动分区 `M16BOOT` 和 348 GiB 的 ext4 根分区 `M16ROOT`。调整前保存 GPT、EFI 内容及完整 Linux 分区镜像，并校验备份与源分区的 SHA-256。检查 NTFS 一致性并完成 `ntfsresize --no-action` 验证后，先缩小 NTFS，再调整 Windows 分区边界；Windows 起始扇区和所有分区标识保持一致。

Windows 后方依次是 Linux 启动分区和根分区。扩容时从安装 U 盘启动，将全部 SSD 分区卸载，把两个 Linux 分区复制到缩减 Windows 所释放的空间。逐字节比较原分区与副本，通过后更新分区表，并使用 `resize2fs` 扩展根文件系统。文件系统 UUID 和卷标保持一致，操作完成后检查 GPT、FAT 和 ext4。

`M16ROOT` 挂载到 `/mnt`，`M16BOOT` 挂载到 `/mnt/boot`，原 EFI 分区（UUID `6219-21FA`）挂载到 `/mnt/efi`。GRUB 在原 EFI 分区保存启动程序，将配置、内核和 initrd 放在 `/boot`，默认选择 NixOS，等待 5 秒后启动。菜单提供 Windows 选项，通过 EFI 分区 UUID 定位原有 Windows 启动程序。

固件中的系统启动项为 `GRUB`，指向原 EFI 分区的 `\EFI\BOOT\BOOTX64.EFI`。GRUB 使用 `efiInstallAsRemovable` 安装至该标准路径，系统更新通过文件更新引导程序。Windows 启动程序保存为 `\EFI\Microsoft\Boot\windows.efi`，由 GRUB 菜单加载；这个文件名避免华硕固件自动生成 Windows Boot Manager 启动项。系统部署和 `m16-boot-entries.service` 会将 Windows 更新生成的 `bootmgfw.efi` 移至 `windows.efi`。

每次 NixOS 启动时，`m16-boot-entries.service` 使用 `efibootdump` 识别名称为 Windows Boot Manager、指向本机 EFI 分区的启动项，将变量备份到 `/var/lib/m16-boot-entries` 后删除。GRUB 的启动项及菜单中的 Windows 入口保持可用。

2026-10-03 已新增 300 GiB，将 NixOS 总分配容量扩展到 350 GiB。扩容后的 Windows 分区约 126.63 GiB，空闲约 45.46 GiB，NTFS 一致性检查通过。

| 分区 | 容量 | 文件系统 | 用途 |
| --- | --- | --- | --- |
| `nvme0n1p1` | 300 MiB | FAT32 | 原 EFI 分区，挂载到 `/efi` |
| `nvme0n1p2` | 16 MiB | Microsoft Reserved | Windows 保留分区 |
| `nvme0n1p3` | 约 126.63 GiB | NTFS | Windows |
| `nvme0n1p4` | 2 GiB | FAT32，`M16BOOT` | Linux 启动分区，挂载到 `/boot` |
| `nvme0n1p5` | 348 GiB | ext4，`M16ROOT` | NixOS 根分区 |

### 系统和用户环境部署

将安装介质的 `/iso/installer-network.env` 以 root 所有、权限 `0600` 写入目标系统 `/var/lib/NetworkManager/m16-wifi.env`。NetworkManager 使用该文件生成持久 Wi-Fi 连接。

本地登录密码通过 `users.users.<name>.hashedPasswordFile` 管理，散列分别保存在 `/var/lib/user-passwords/linwhite` 和 `/var/lib/user-passwords/hank`，文件仅允许 root 读写。安装前创建这些文件，密码及散列均保留在仓库以外。

两个账户各自生成独立的 Ed25519 密钥，保存在本机 `~/.ssh/id_ed25519`。对应的 age 公钥加入 `secrets/clients/cliproxy.yaml` 的接收者列表，供 Home Manager 的 sops-nix 服务解密 OpenCode 凭据。

系统和两个 Home Manager 环境可以在 tank 构建，再通过 `nix copy` 写入安装机的 `/mnt` store。安装使用 `nixos-install --root /mnt --system <system-store-path> --no-root-passwd --no-channel-copy`，两个 Home Manager 环境分别以对应账户执行其 `activate` 程序。初次安装的三个环境合计约 17.6 GiB。

后续更新分别执行系统部署及 `just hm m16 hank`、`just hm m16 linwhite`。Tailscale 身份已在安装期间注册并写入目标系统，首次启动后由系统服务使用持久状态连接。

2026-10-03 已完成系统安装及两个独立 Home Manager 环境的激活。在目标系统中验证了两个账户的 GNOME PAM 密码认证、sops-nix 凭据解密、交互式 Zsh、Git、tmux 会话和 Neovim 启动。根分区扩容后可用容量约 319.71 GiB。

扩容后已在 U 盘保持连接的情况下，验证通过 SSD 上的 GRUB 默认启动 NixOS，根分区为 `nvme0n1p5`。Wi-Fi、局域网 SSH、Tailscale SSH、GNOME 登录服务和 NVIDIA 驱动正常，系统及两个用户均没有失败的 systemd 服务。系统和两个 Home Manager 环境均保留扩容前的版本，凭据解密、Zsh、tmux 和 Neovim 启动检查通过。安装时已验证 hank 通过 Podman 的 NVIDIA CDI 在容器中调用 `nvidia-smi`，识别到 RTX 3060 Laptop GPU、6144 MiB 显存和 595.71.05 驱动。

安装后已通过 GRUB 的 Windows 菜单项启动保留的 Windows 系统，并确认 `m16-windows` 在 Tailscale 上联网。扩容后再次检查 NTFS 一致性和 Windows EFI 启动程序的 SHA-256，检查通过。

ELECOM U 盘持续连接，作为专用维护启动盘，启动时按住 Esc 可以选择。固件将 SSD 上的 GRUB 排在 U 盘之前。U 盘保留自动联网和 SSH 功能，其 EFI 启动文件与原始备份的 SHA-256 一致。GPT、EFI 内容、启动项和扩容前的完整 Linux 分区备份保存在操作机受保护、被 Git 忽略的工作目录中。
