# 268V Windows 虚拟机与核显直通

2026-10-02。目标是在 268V 上准备可回退的 KVM / Windows 11 / Arc 140V
整卡直通实验环境。配置、网络、磁盘定义与 ROM 构建均由 Nix 管理。
**尚未验证核显驱动接管、内屏输出或命运 2 实际运行。**

本次已通过普通/VFIO 系统完整构建、三份 domain XML schema 校验和 ROM 构建。
另以普通用户启动了隔离的 QEMU/KVM + OVMF + TPM 2.0 测试，确认固件正常到达
“无可启动设备”画面，随后结束测试进程；该测试没有接触实体核显或物理磁盘。
普通系统配置已通过 `just switch 268v` 激活，`libvirtd` 运行正常，
`nixvirt` 声明应用成功，已创建并启动持久 `windows11` VM、独立磁盘与 NAT 网络。
运行参数为 6 vCPU、16 GiB；宿主 GNOME 保持运行，没有切换至 VFIO 启动项。
通过 `b650` 的 Tailscale SSH 回连 `268v` 并运行 `virsh list` 已成功，确认远程
管理链路可用。本机使用 Tailscale SSH，`sshd.service` 不运行并不代表 SSH 不可达。
随后用户下载了 `Windows11_Client_x64_en-us_26300_9457.iso`（9,047,330,816 字节），
SHA256 `bd4307df32bc8af33b39ccecb1174aeb345386630f89a2b86c7a4e36b55ea650`
与 Microsoft 下载页英文 x64 项一致。已复制到运行时路径
`/var/lib/libvirt/iso/windows11.iso` 并再次校验 SHA256。
安装器已加载 VirtIO 光盘的 `viostor/w11/amd64` 驱动，确认唯一安装目标为
240 GiB 空白虚拟磁盘。Windows 11 Pro（英文，26300.9457，跳过产品密钥）
已安装，用户完成首次设置并进入 `hank` 桌面。
OOBE 中已用 `pnputil` 安装 `NetKVM/w11/amd64/netkvm.inf`，获得 NAT DHCP 地址，
`curl.exe -I https://www.microsoft.com` 返回 HTTP 200。
正常关闭客户机后，已移除安装光盘声明（`installISO` 恢复默认 `null`）；
再次应用配置并启动客户机，确认能从虚拟硬盘回到 OOBE，网卡驱动保留。
VirtIO 驱动光盘保留。物理 Windows 分区没有挂载或传入。
首次登录后补装 `E:\fwcfg\w11\amd64\fwcfg.inf`，解决唯一的
`ACPI\QEMU0002` Code 28；再次运行 `pnputil /enum-devices /problem` 无问题设备。
普通模式显示设备为 Microsoft Basic Display Adapter（`1234:1111`），符合软件 VGA 定义。

已从 [Intel 官方 Arc 驱动页](https://www.intel.com/content/www/us/en/download/785597/intel-arc-graphics-windows.html)
下载明确列出 Arc 140V / 268V 的 `gfx_win_101.9033.exe` 到宿主 `~/Downloads/`，
SHA512 与官方值一致：
`e36933d5af3bed5cd39290eab29ec2e0fe7995b3f9ecfe8c4ef396c7e16b06f02fe97651e44f79f787bf143b45b63d4460fa6399d3235daa69b6d953dc5b8987`。
安装包也已复制到客户机 `C:\Users\Public\Downloads\Intel.exe`，客户机内
`certutil -hashfile ... SHA512` 再次校验一致。传输时仅在 VM 网桥地址临时监听，
传输结束已停止该 HTTP 服务。另将原安装包的 Graphics 目录解包至客户机
`C:\IntelDrivers\Graphics`，确认 `iigd_dch.inf` 声明 `8086:64a0`，
并用 `pnputil /add-driver C:\IntelDrivers\Graphics\*.inf /subdirs` 预置到驱动库。
12 个驱动包均成功加入；`pnputil /enum-drivers /class Display` 确认主驱动
版本为 `32.0.101.9033`，签名者为 Microsoft Windows Hardware Compatibility Publisher。
预置不代表驱动已绑定或加速可用；核显实际传入后仍需检查设备状态。

## 首次重启测试的接续位置

2026-10-02 用户授权实际切换 VFIO。测试工具在 `scripts/vfio-probe/`：
控制程序由 **b650 的 root transient systemd service** 运行，不能在 268V 本机运行。
当前固定使用已核实的 Generation 12 普通与 VFIO 条目，重新构建后不要直接照跑。
Windows 的 `VFIOProbe` 一次性启动任务以 SYSTEM 收集显卡及问题设备列表，
向仅监听 VM 网桥的临时接收端提交 JSON，然后自行删除任务。
接收服务有 600 秒运行上限，不开启公共监听，也不自动登录 Windows。

控制程序先正常关闭 VM，使用一次性 VFIO 启动项重启，核实 GPU 已绑定
`vfio-pci` 后启动 VM。拿到 Windows 报告或等待超时后保存日志、控制台截图，
正常请求关闭 VM，再重启返回普通 NixOS。若 Windows 不响应 ACPI 关机，
等待 90 秒后仍会请求宿主重启以恢复桌面；这是首次直通实验的恢复流程。
宿主若失联到无法接收重启命令，则需物理重启；默认启动项一直保留普通 NixOS。

结果保存在 **b650** 的 `/var/tmp/268v-vfio-probe/`：`controller.log`、
`host.txt`、`start.txt`、`guest.json`、`kernel.log`、`qemu.log`、`screen.png`、
`restored.txt`。恢复 Codex 后先读取这些文件，不要把“已安排测试”当成直通成功。
宿主本身也保留接收到的 `/var/tmp/268v-vfio-probe/guest.json`；
Windows 本地报告在 `C:\IntelDrivers\vfio-report.json`。

```sh
tailscale ssh root@b650 'cat /var/tmp/268v-vfio-probe/controller.log'
tailscale ssh root@b650 'cat /var/tmp/268v-vfio-probe/guest.json'
```

tmux 与 Codex 都是宿主进程，不能跨 268V 重启存活；仅关闭 SSH 或终端时才是
tmux 的保活场景。独立的 b650 控制程序不依赖本机 Codex 会话继续运行。

首次启动控制服务时，等待结束后立即报
`neither $XDG_CONFIG_HOME nor $HOME are defined`，因此没有关闭 VM 或重启宿主。
误导点是交互式 Tailscale SSH 已成功，但 systemd 的隐式 root 服务没有同样的登录环境。
控制服务必须显式指定 `User=root`、`SetLoginEnvironment=yes`；现已加入等待前的
完整连接检查和 `--check` 只读预检模式，先在相同服务环境中通过预检再执行。

```sh
# 在 b650 上运行；脚本已复制到对应运行时目录。
systemd-run --wait --pipe --collect --property=User=root --property=SetLoginEnvironment=yes \
  /run/current-system/sw/bin/bash /var/tmp/268v-vfio-probe/controller.sh --check
systemd-run --unit=268v-vfio-probe --property=User=root --property=SetLoginEnvironment=yes \
  --property=RuntimeMaxSec=1800 /run/current-system/sw/bin/bash /var/tmp/268v-vfio-probe/controller.sh
```

## 命运 2 的限制与证据

Bungie 安全团队 BNGSecurity 在 2021-08-26 的
[官方答复](https://www.bungie.net/en/Forums/Post/259501907)明确表示，
虚拟机实现方式不构成例外，检测到在 VM 内游玩会封禁账号。
[现行封禁政策](https://help.bungie.net/hc/en-us/articles/360049517431-Destiny-Account-Restrictions-and-Banning-Policies)
也提及虚拟机；[BattlEye 支持说明](https://help.bungie.net/hc/en-us/articles/4404072197140-BattlEye-Anti-Cheat-Support-Guide)
确认命运 2 使用该反作弊。因此不能用其他 BattlEye 游戏的运行经历推导命运 2 的许可。

目前没有找到能独立复现、适用于本机版本并能证明账号安全的命运 2 KVM 方案。
官方未公开完整检测实现。下表是公开 VM 检测研究所覆盖的面，
**不是已证实的命运 2 检测规则清单**。

| 检测面 | 公开研究内容 | 本配置的边界 |
| --- | --- | --- |
| CPUID 内容 | hypervisor 位、厂商叶、拓扑与功能一致性 | 可选隐藏 hypervisor 位和 KVM 签名 |
| 固件与设备 | SMBIOS、ACPI、OVMF、PCI 设备、磁盘和网卡特征 | 保留标准 QEMU 设备，未伪造整个平台 |
| 操作系统痕迹 | VirtIO 驱动、服务、注册表和软件 TPM | Windows 功能所需设备照常存在 |
| 执行时序 | CPUID 导致 VM-exit 的额外耗时、多核与多时钟交叉测量 | 没有进行计时补偿 |
| 指令与异常行为 | CPU/MSR/异常模拟和嵌套虚拟化行为差异 | 标准 KVM/QEMU，未修改实现 |

主要研究资源：

- [VMAware 源码](https://github.com/NotRequiem/VMAware)与
  [检测项文档](https://github.com/NotRequiem/VMAware/wiki/Documentation)：
  可用于离线比较不同 VM 配置暴露的特征；其检测结果不代表 BattlEye 的结果。
- [al-khaser 源码](https://github.com/ayoubfaouzi/al-khaser)：
  通用反虚拟机、反调试测试集合。不是命运 2 专用验证器。
- [qemu-anti-detection](https://github.com/zhaodice/qemu-anti-detection)：
  修改 QEMU 暴露特征的已有探索。项目声明不构成本机或命运 2 的兼容性证据；
  此次没有套用其补丁，也没有用它替换 Nixpkgs 的 QEMU。
- [2022 年 Hyper-V 嵌套方式失效的使用者记录](https://www.reddit.com/r/VFIO/comments/wlkgwv/)：
  这是其他 BattlEye 游戏的历史一手使用报告，说明旧教程可能失效，不能外推当前命运 2。
- [2023 年命运 2 使用者讨论](https://www.reddit.com/r/VFIO/comments/1331pmg/)：
  发帖者报告过有限测试，但并非持续实际游玩验证，也不能反驳官方封禁规则。

## CPUID 延迟与内核补丁

隐藏 CPUID 的返回内容与隐藏执行延迟是两件不同的事。Intel VMX 的 CPUID
执行会触发 VM-exit，`host-passthrough`、关闭 `hypervisor` 位、设置 KVM hidden
均不会取消这一硬件行为。

[Unintercept CPUID 作者的研究](https://virtfunc.com/projects/unintercept-cpuid/)
利用 AMD SVM 可关闭 CPUID 拦截的能力，并讨论了启动和功能集一致性问题。
这不是可直接用于 Intel 268V 的补丁。Intel 上若研究时间补偿，通常需要修改
宿主 KVM 的退出或客户机计时处理路径；不存在一个能用 XML 打开的标准“消除延迟”选项。

补偿单次 RDTSC 测量不代表解决多核、调度和不同时间源的一致性。
参见 [KVM 时间虚拟化文档](https://docs.kernel.org/virt/kvm/x86/timekeeping.html)。
未获得适配本机内核并验证过的补丁，因此没有修改宿主内核的反检测行为。
以后如开展此实验，应使用单独启动项、固定补丁版本，并分别记录宿主裸机和客户机测量。
“通用检测器零命中”仍不能当作命运 2 通行证。

## 本机勘察

| 项目 | 2026-10-02 实测 |
| --- | --- |
| 主机 | `268v`，Lenovo，Ultra 7 268V，8 核 / 8 线程 |
| 核显 | `0000:00:02.0`，`8086:64a0`，Lunar Lake / Arc 140V，宿主驱动 `xe` |
| 隔离 | 核显独占 IOMMU group 3；无需 ACS override |
| 复位 | sysfs `reset_method` 为 `flr`；仍需实测重复启动 |
| KVM | 宿主实际存在 `/dev/kvm`，已加载 `kvm_intel` |
| 核显共享 | 当前没有 `mdev_supported_types` 或 `sriov_totalvfs` 接口 |
| 内存 | 约 30 GiB 可用物理容量；检查时约 13 GiB available |
| 磁盘 | 根文件系统检查时约 308 GiB 空闲；Windows 与 NixOS 同盘 |
| 物理 Windows | `/dev/nvme0n1p2`，552 GiB NTFS，不交给 VM |
| 软件 | 锁定的 QEMU 10.2.4、libvirt 12.2.0、NixVirt 0.6.0 |

第一次在执行沙箱里看不到 `/dev/kvm`，那是设备隔离，不是 BIOS 未开启虚拟化；
在实际宿主检查已排除。另一个容易误判的地方是 `nixos-hardware` 显式把 `xe`
放进 initrd：只 blacklist 不够，VFIO 启动项已覆盖 initrd 强制加载列表。

## 声明的内容

- `nixos/hosts/268v/virtualisation.nix`：libvirtd、NixVirt、启动项及可调整选项。
- `nixos/hosts/268v/windows-domain.nix`：Windows 硬件定义，通过 NixVirt 生成 XML。
- `pkgs/vfio-igd-rom/default.nix`：固定 VfioIgdPkg 源码和 hash，用 Nixpkgs EDK2
  构建 `8086:64a0` 的 `IgdAssignmentDxe` Option ROM，不包含 Intel 私有 GOP。

默认 VM 是 `windows11`：6 vCPU、16 GiB 内存、240 GiB 稀疏 qcow2、
VirtIO 磁盘/网卡、TPM 2.0、UEFI、软件 VGA 与仅监听回环地址的 SPICE。
240 GiB 是虚拟容量，文件会随写入增长；游戏更新或快照前要检查宿主剩余空间。
现有卷只在不存在时创建，修改容量声明不会自动扩容已有磁盘。

OVMF 使用支持 Secure Boot 的固件及未注册密钥的变量模板，实验基线不启用
Secure Boot 强制验证，以允许加载自建未签名 ROM。不要把这个状态写成
“Secure Boot 已开启”。NVRAM 和 TPM 状态属于持久数据，应与磁盘一起备份。

普通启动保持 GNOME 与 `xe`；`vfio` 启动项在 initrd 把核显交给 VFIO，
关闭宿主显示管理器，并给同一个 Windows 定义增加核显。不能从正在使用核显的
桌面会话直接切换到该特化，需要重新启动。不要把整块 NVMe、共享 USB 控制器、
声卡或 Wi-Fi PCI 功能一起传入；本机内置键盘/触摸板也没有自动传入。
安装和调试阶段用另一台电脑上的 SPICE 输入及音频。

NixVirt 声明的 network/pool/domain 列表会管理连接中的全部对应对象，未列出的
对象会被取消定义。本次勘察该机器未安装运行 libvirt，`/var/lib/libvirt` 不存在；
以后新增 VM 应一并写入声明，不能假定 virt-manager 新建的定义会被保留。
Windows 默认不自动启动，重新应用配置保留其运行状态且不强制重启。

## 安装与首次直通

1. 在 [Microsoft 官方页面](https://www.microsoft.com/software-download/windows11)
   获取 Windows 11 x64 ISO，并按页面给出的 SHA256 核验。此次自动请求下载链接
   被 Microsoft 的 Sentinel 拒绝，未下载或使用第三方系统镜像。
   已下载的镜像位于私有家目录，QEMU 用户无法遍历；先复制到运行时位置：

   ```sh
   sudo install -D -m 0644 /home/hank/Downloads/Windows11_Client_x64_en-us_26300_9457.iso /var/lib/libvirt/iso/windows11.iso
   ```

   重新安装时在 `system.nix` 临时声明（当前安装完成，已恢复 `null`）：

   ```nix
   my.windowsVM.installISO = "/var/lib/libvirt/iso/windows11.iso";
   ```

2. 按 `AGENTS.md` 完成 fetch / freshness 检查后应用普通系统配置：

   ```sh
   just switch 268v
   systemctl status libvirtd nixvirt
   virsh -c qemu:///system list --all
   virsh -c qemu:///system start windows11
   virt-manager --connect qemu:///system
   ```

   初次启动需在控制台及时按键从安装光盘启动；必要时用 UEFI boot menu。
   Windows 安装器里从附带 VirtIO 光盘载入 `viostor/w11/amd64` 存储驱动，
   联网时载入 `NetKVM/w11/amd64`。内存不足时先退出大型应用，或减少声明的内存。
   正常安装 Windows，完成更新后安装 Intel 对应 Lunar Lake 的官方显卡驱动。
   完成安装后把 `installISO` 改回 `null` 并在 VM 关机状态应用配置。

3. 确认另一台设备能 SSH 到 `hank@268v.inner.imdomestic.com`。
   Tailscale CLI 可用时也可使用 `tailscale ssh hank@268v`，它处理 tailnet 主机密钥。
   关闭 VM，重新启动宿主，在 systemd-boot 菜单选择带 `vfio` 标记的条目。
   这个启动阶段宿主屏幕可能黑屏，普通条目始终保留。
   2026-10-02 已核实当前 Generation 12 的条目是
   `nixos-generation-12-specialisation-vfio.conf`；后续 rebuild 后以 `sudo bootctl list` 为准。

4. 从另一台设备检查：

   ```sh
   lspci -nnk -s 00:02.0
   cat /sys/bus/pci/devices/0000:00:02.0/reset_method
   systemctl status nixvirt
   virsh -c qemu:///system dumpxml --inactive windows11
   ```

   必须看到核显驱动为 `vfio-pci`，XML 中存在 `00:02.0` hostdev 与 ROM，
   然后手动启动 `windows11`。远程 virt-manager 使用
   `qemu+ssh://hank@268v.inner.imdomestic.com/system`，SPICE 不向 LAN 公网监听。

5. 先用设备管理器、`dxdiag` 和普通 3D 程序验证显卡驱动及加速，检查 Code 43、
   内屏/HDMI 输出、休眠和重复关机开机。核显不初始化时检查
   `/var/log/libvirt/qemu/windows11.log`、`journalctl -b -k` 和 OpRegion/ROM 加载。
   自建 ROM 不提供 GOP 开机画面；驱动接管后的内屏输出仍是待验证项。
   这些测试通过后也不能推导命运 2 的检测与账号安全。

6. 退出时先正常关闭 Windows，再重启宿主选择普通 NixOS 条目恢复 GNOME。
   此方案不依赖热拔核显或退出 VM 后在线重新绑定 `xe`。

QEMU 对现代 Intel IGD 的要求、固件限制与排查依据：
[与锁定版本一致的 IGD 文档](https://github.com/qemu/qemu/blob/v10.2.4/docs/igd-assign.txt)、
[VfioIgdPkg 上游](https://github.com/tomitamoeko/VfioIgdPkg)。
Lunar Lake 不应照抄 Gen6–9 的 legacy VGA 参数；本配置保留 Q35 和软件显示，
启用 OpRegion，关闭 legacy mode。尚未通过实机测试的部分包括 Windows 驱动、
ROM 在此固件上的运行效果及内屏连接拓扑。

## 基础特征隐藏开关

在 `system.nix` 声明 `my.windowsVM.hideHypervisor = true;`，会关闭 CPU 的
hypervisor 标志、开启 KVM hidden，并去掉显式 Hyper-V enlightenments 与
hypervclock。默认关闭，便于先建立正常运行的基线。改变后需正常关闭客户机并
重新应用配置，再启动客户机；不要在 NixVirt 管理的 VM 上长期手工编辑 XML。

这不会隐藏 VirtIO、OVMF、TPM、固件表、虚拟硬件或 CPUID 时序，且可能影响性能。
没有随机篡改硬件序列号、替换系统驱动或安装反作弊绕过程序。
相关原生选项见 [libvirt domain 文档](https://libvirt.org/formatdomain.html)。

## 验证命令

```sh
nix eval --raw .#nixosConfigurations.268v.config.system.build.toplevel.drvPath
nix build --no-link .#nixosConfigurations.268v.config.my.windowsVM.igdROM --max-jobs 2 --cores 4
nix build --no-link .#nixosConfigurations.268v.config.system.build.windowsVMChecks --max-jobs 2 --cores 4
nix build --no-link .#nixosConfigurations.268v.config.system.build.toplevel --max-jobs 2 --cores 4
```

`windowsVMChecks` 用 libvirt 的 Relax NG schema 验证普通、VFIO、VFIO 加基础隐藏
三份 XML，同时检查 ROM、固件和 VirtIO 光盘真实存在。这不代替实际 PCI 设备测试。

启用的是独立系统模块，不涉及 Home Manager；`just hm` 不会应用这里的改动。
