# seraph：systemd-boot + Lanzaboote 安全启动

配置在 `hosts/seraph/system.nix`，Lanzaboote 的稳定版本在 `flake.nix` / `flake.lock`。
**配置启用不等于固件已经开启 Secure Boot**：安装、密钥注册、重启验证是分开的步骤。

## 布局与约束

- Linux ESP：`/boot`，UUID `8DC1-C232`，2 GiB。
- Windows ESP：`/windows-efi`，UUID `8C8A-383D`，在另一块 NVMe 上。
- 自签名的 PK / KEK / db 私钥：`/var/lib/sbctl`，只允许 root 读取；不进 Git / Nix store。
- GRUB 停用。`boot.loader.systemd-boot.enable = false` 是刻意的：Lanzaboote 的安装器
  安装并签名 systemd-boot 和 NixOS UKI，而不是运行 NixOS 自带的 unsigned 安装器。
- 最多保留 5 代；禁用启动菜单的内核参数编辑；拒绝无密钥时安装未签名镜像。
- 不自动生成或注册密钥，也不自动重启。密钥丢失时应恢复备份，不能随手重建一套。

systemd-boot 不会像 GRUB 一样跨 ESP 搜索并 chainload Windows。安装包装器和
`seraph-boot-entries.service` 把 Windows 的 **整个** `EFI/Microsoft` 目录（包括 BCD、
语言文件）同步到 Linux ESP；不能只复制一个 `.efi`。菜单仍通过原生
`boot.loader.systemd-boot.extraEntries` 声明，由包装器安装，因为 Lanzaboote 停用了
原生模块，不会自动处理它的 `extraEntries`。

保留原有 `bootmgfw.efi → windows.efi` 重命名和清理 Windows NVRAM 启动项的行为，
避免本机固件重新抢回 Windows 为默认。Windows 的签名不因重命名或复制而改变；
注册时保留 Microsoft 证书。Windows 更新后，下次进入 NixOS 或安装新代会重新同步。

Lanzaboote 同时写入 `EFI/systemd/systemd-bootx64.efi` 和 `EFI/BOOT/BOOTX64.EFI`。
本机现有 NVRAM 项指向后一条 fallback 路径，可以继续使用；标签暂时仍可能显示
`GRUB NixOS ms7e56`，不代表实际仍由 GRUB 启动。不必运行一个 unsigned 的
`bootctl install`，也不必为此次迁移改写 BootOrder。

## 1. 准备和备份

先准备可用的 NixOS UEFI 救援盘，并确保能在机器旁进入固件设置。
如果 Windows 使用 BitLocker / 设备加密，**先导出并核对恢复密钥**，必要时暂停保护：
更换引导程序和 Secure Boot 密钥会改变 TPM 测量，可能要求恢复密钥。

每次 rebuild 前按 `AGENTS.md` 做 freshness check：fetch、同步远端和检查本地改动，
比较运行中的 `/run/current-system` 与当前配置 `outPath`；不要部署旧 checkout。
本机 GitHub SSH 认证不可用时，可以用 HTTPS fetch（不会绕过主机密钥校验）：

```sh
git fetch https://github.com/imdomestic/nix-config.git '+refs/heads/main:refs/remotes/origin/main'
git status --short --branch
git log --oneline HEAD..origin/main
# 有新提交时先 rebase，处理冲突并重新验证。
readlink /run/current-system
nix eval --raw .#nixosConfigurations.seraph.config.system.build.toplevel.outPath
```

备份两个 ESP；目录含引导配置，限制为 root 可读：

```sh
sudo install -d -m 0700 /root/seraph-boot-backup
sudo tar -C /boot -cpf /root/seraph-boot-backup/linux-esp.tar .
sudo tar -C /windows-efi -cpf /root/seraph-boot-backup/windows-esp.tar .
sudo efibootmgr -v | sudo tee /root/seraph-boot-backup/efibootmgr.txt
```

另外在固件中导出当前 Secure Boot 证书 / dbx（如果固件支持）。不要使用会连带清空
吊销列表 dbx 的 “Clear All Secure Boot Keys”。只移除 PK 或进入 Setup Mode。

## 2. 生成密钥、安装签名引导程序

第一次先使用仓库所钉 nixpkgs 的 sbctl，无需先激活新系统：

```sh
sbctlPackage=$(nix build --no-link --print-out-paths --inputs-from . nixpkgs#sbctl)
sudo "$sbctlPackage/bin/sbctl" create-keys
```

若已有 `/var/lib/sbctl/keys`，不要重新生成；先检查原有密钥。生成后把
`/var/lib/sbctl` 备份到安全的离线介质，私钥不能放在 ESP 或提交到 Git。

先构建和检查闭包差异，然后只安装到下一次启动，不切换正在运行的服务：

```sh
nix build .#nixosConfigurations.seraph.config.system.build.toplevel --max-jobs 2 --cores 8
nix store diff-closures /run/current-system ./result
nixos-rebuild --sudo boot --install-bootloader --flake .#seraph --max-jobs 2 --cores 8
sudo "$sbctlPackage/bin/sbctl" verify
sudo bootctl --esp-path=/boot list
```

核对：

- `EFI/BOOT/BOOTX64.EFI`、`EFI/systemd/systemd-bootx64.efi`、`EFI/Linux/nixos-*.efi`
  均有自签名，`bootctl list` 能看到 NixOS 和 Windows。
- `EFI/nixos/*-kernel-*.efi` 和 initrd 是 Lanzaboote 校验哈希的外置载荷，
  **没有 PE 签名是正常的**，不能把 `sbctl verify` 的这些报告当作安装失败。
- Windows 文件保留 Microsoft 签名，不必也不应靠 `sbctl sign-all` 改成自签名。
  `sbctl verify` 不一定把 Microsoft 签名认作本机 db 密钥的签名。

**保持 Secure Boot 关闭，先重启验证 systemd-boot 能启动 NixOS，且 Windows 菜单可用。**
进入 NixOS 后用 `sudo bootctl status` 确认 Current Boot Loader 是 systemd-boot。
此前不要直接在固件里启用安全启动，否则现有 GRUB 可能被拒绝。

## 3. 注册密钥并开启 Secure Boot

在固件中进入 Secure Boot Custom / Setup Mode（通常只删除 Platform Key / PK），
保留 dbx。返回 NixOS 后：

```sh
sudo sbctl status
# 确认 Setup Mode 为 Enabled 后才继续：
sudo sbctl enroll-keys --microsoft --firmware-builtin
```

`--microsoft` 兼容 Windows 和 Microsoft 签名的显卡 Option ROM；
`--firmware-builtin` 保留厂商预置证书。若 sbctl 报 Option ROM 风险，停下来调查，
**不要**加 `--yes-this-might-brick-my-machine` 强制绕过。

在固件里确认 Secure Boot 已启用、使用已注册的自定义密钥，而不是恢复成仅信任
出厂证书的 Standard 模式。重启后检查：

```sh
sudo sbctl status
sudo bootctl status
sudo sbctl verify
systemctl --failed
nvidia-smi
```

应为 Secure Boot enabled、Setup Mode disabled、Current Boot Loader systemd-boot。
再验证 Windows 启动 / BitLocker，并确认固件中的 dbx 没有被清空。

本机根文件系统是未加密 ext4：root-only 私钥权限只能防止普通运行中用户读取，不能
防离线磁盘修改。真正抵御物理攻击还需磁盘保护、固件密码和固件更新；此次不改磁盘布局。

## 恢复

启动失败时先在固件关闭 Secure Boot，再选择旧 NixOS generation。
Lanzaboote 会把保留的旧代也安装成签名 UKI，不应在 Secure Boot 开着时恢复 unsigned GRUB。
若连菜单也无法进入，使用 UEFI 救援盘挂载根分区和两个 ESP，按备份恢复相应引导文件。

独立恢复 Windows 时，先关闭 Secure Boot 或确认 Microsoft 证书仍被信任，然后在救援
环境恢复 `/windows-efi/EFI/Microsoft/Boot/windows.efi` 为 `bootmgfw.efi` 并重建其固件项。
旧的启动项清理服务会再次改名，恢复排查期间应停用它。

永久退出 Lanzaboote 必须先关闭 Secure Boot，再改配置和安装 unsigned 引导程序。
不要删除唯一一套 `/var/lib/sbctl` 私钥，否则以后 rebuild 无法继续签名。

上游参考：[准备系统](https://nix-community.github.io/lanzaboote/getting-started/prepare-your-system.html)、
[开启安全启动](https://nix-community.github.io/lanzaboote/getting-started/enable-secure-boot.html)。
