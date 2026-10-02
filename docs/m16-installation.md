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

主机定义位于 `nixos/hosts/m16/`，用户环境为 `homeConfigurations."linwhite@m16"`。连接实机后核对硬件和目标磁盘，完成分区并挂载到 `/mnt`，使用实机生成的 `hardware-configuration.nix` 更新主机配置。

系统安装使用 `nixos-install --flake .#m16`。用户环境独立安装，在 linwhite 账户下执行 `just hm m16 linwhite`。系统和 Home Manager 分别验证，重启后检查网络、SSH、图形桌面及用户环境。
