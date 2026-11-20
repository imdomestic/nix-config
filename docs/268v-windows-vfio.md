# 268V Windows 虚拟机与核显直通

268V 上可回退的 KVM / Windows 11 / Arc 140V 整卡直通实验环境。配置、网络、磁盘定义与
ROM 构建均由 Nix 管理。

**现状（2026-10-09）**：移除软件 VGA 后 Code 43 消失（第九轮）；Arc 140V 通过离屏
Direct3D 绘制及像素读回（第十轮）。内屏输出只在第十一轮被用户偶然看到，没有确认稳定；
本机键盘可用，触控板改用 libinput 转换（第十三轮已部署，Windows 里的手感未验证）。
命运 2 没有测试，也不应测试（见下）。

## 声明的内容

- `hosts/268v/virtualisation.nix`：libvirtd、NixVirt、启动项及可调整选项。
- `hosts/268v/windows-domain.nix`：Windows 硬件定义，通过 NixVirt 生成 XML。
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
关闭宿主显示管理器，并给同一个 Windows 定义增加核显。VFIO specialisation 声明
`softwareDisplay = false`（第九轮的结论）、`hideHypervisor = true`、`localInput = true`；
普通模式保留软件控制台。不能从正在使用核显的桌面会话直接切换到该特化，需要重新启动。
不要把整块 NVMe、共享 USB 控制器、声卡或 Wi-Fi PCI 功能一起传入。

NixVirt 声明的 network/pool/domain 列表会管理连接中的全部对应对象，未列出的
对象会被取消定义；新增 VM 要一并写入声明，virt-manager 新建的定义不会被保留。
Windows 默认不自动启动，重新应用配置保留其运行状态且不强制重启。

## 本机勘察

| 项目 | 2026-10-02 实测 |
| --- | --- |
| 主机 | `268v`，Lenovo，Ultra 7 268V，8 核 / 8 线程 |
| 核显 | `0000:00:02.0`，`8086:64a0`，Lunar Lake / Arc 140V，宿主驱动 `xe` |
| 隔离 | 核显独占 IOMMU group 3；无需 ACS override |
| 复位 | sysfs `reset_method` 为 `flr` |
| KVM | 宿主实际存在 `/dev/kvm`，已加载 `kvm_intel` |
| 核显共享 | 没有 `mdev_supported_types` 或 `sriov_totalvfs` 接口 |
| 内存 | 约 30 GiB 可用物理容量 |
| 物理 Windows | `/dev/nvme0n1p2`，552 GiB NTFS，不交给 VM |
| 软件 | 锁定的 QEMU 10.2.4、libvirt 12.2.0、NixVirt 0.6.0 |

第一次在执行沙箱里看不到 `/dev/kvm`，那是设备隔离，不是 BIOS 未开启虚拟化。
另一个容易误判的地方是 `nixos-hardware` 显式把 `xe` 放进 initrd：只 blacklist 不够，
VFIO 启动项已覆盖 initrd 强制加载列表。

## 安装与首次直通

1. 在 [Microsoft 官方页面](https://www.microsoft.com/software-download/windows11)
   获取 Windows 11 x64 ISO，并按页面给出的 SHA256 核验（自动请求下载链接会被
   Microsoft 的 Sentinel 拒绝）。镜像要放在 QEMU 用户能读的位置：

   ```sh
   sudo install -D -m 0644 ~/Downloads/<windows>.iso /var/lib/libvirt/iso/windows11.iso
   ```

   重新安装时在 `system.nix` 临时声明 `my.windowsVM.installISO = "/var/lib/libvirt/iso/windows11.iso";`，
   装完改回 `null` 并在 VM 关机状态应用配置。

2. 按 `AGENTS.md` 完成 freshness 检查后应用普通系统配置：

   ```sh
   just switch 268v
   systemctl status libvirtd nixvirt
   virsh -c qemu:///system list --all
   virsh -c qemu:///system start windows11
   virt-manager --connect qemu:///system
   ```

   Windows 安装器里从附带 VirtIO 光盘载入 `viostor/w11/amd64` 存储驱动，
   联网用 `NetKVM/w11/amd64`；首次登录后补装 `fwcfg/w11/amd64`，否则
   `ACPI\QEMU0002` 报 Code 28。然后预置 Intel 显卡驱动（见下文“驱动”）。

3. 确认另一台设备能 SSH 到 `hank@268v.inner.imdomestic.com`（本机走 Tailscale SSH，
   `sshd.service` 不运行不代表 SSH 不可达）。关闭 VM，重启宿主，在 systemd-boot 菜单选择
   带 `vfio` 标记的条目（以 `sudo bootctl list` 为准）。这个阶段宿主屏幕可能黑屏，
   普通条目始终保留。

4. 从另一台设备检查：

   ```sh
   lspci -nnk -s 00:02.0
   cat /sys/bus/pci/devices/0000:00:02.0/reset_method
   systemctl status nixvirt
   virsh -c qemu:///system dumpxml --inactive windows11
   ```

   必须看到核显驱动为 `vfio-pci`，XML 中存在 `00:02.0` hostdev 与 ROM。
   远程 virt-manager 用 `qemu+ssh://hank@268v.inner.imdomestic.com/system`。

5. 核显不初始化时检查 `/var/log/libvirt/qemu/windows11.log`、`journalctl -b -k` 和
   OpRegion/ROM 加载。自建 ROM 不提供 GOP 开机画面。

6. 退出时先正常关闭 Windows，再重启宿主选择普通 NixOS 条目恢复 GNOME。
   此方案不依赖热拔核显或退出 VM 后在线重新绑定 `xe`。

QEMU 对现代 Intel IGD 的要求与排查依据：
[与锁定版本一致的 IGD 文档](https://github.com/qemu/qemu/blob/v10.2.4/docs/igd-assign.txt)、
[VfioIgdPkg 上游](https://github.com/tomitamoeko/VfioIgdPkg)。
Lunar Lake 不应照抄 Gen6–9 的 legacy VGA 参数；本配置用 Q35，启用 OpRegion，
关闭 legacy mode，GPU 在客户机根总线 `00:02.0`。

## 探测控制程序

`scripts/vfio-probe/controller.sh` 由 **taipan 或 tank 的 root transient systemd service**
运行，不能在会被重启的 268V 本机运行（tmux 和 agent 会话都活不过宿主重启）。它读取当前
system profile 的 generation，确认普通启动条目与运行中的闭包一致，然后：正常关闭 VM →
一次性 VFIO 启动项重启 → 核实 GPU 绑定 `vfio-pci` → 启动 VM → 等 Windows 报告或超时 →
保存日志和截图 → 正常关闭 VM → 重启回普通 NixOS。Windows 不响应 ACPI 关机时，等 90 秒后
仍请求宿主重启；宿主失联到收不到重启命令时只能物理重启，默认启动项一直是普通 NixOS。

Windows 的 `VFIOProbe` 一次性启动任务以 SYSTEM 收集显卡、问题设备、DxgKrnl /
Kernel-PnP 事件、显示器与 VBS 状态，向只监听 VM 网桥的临时接收端（600 秒上限）提交 JSON，
然后删除任务。`firmware.py` 从 Q35 ECAM 读取客户机 `00:02.0` 的 PCI 配置、ASLS 和
OpRegion / VBT 签名。

```sh
# 在 taipan 或 tank 上；脚本已复制到 /var/tmp/268v-vfio-probe/。
systemd-run --wait --pipe --collect --property=User=root --property=SetLoginEnvironment=yes \
  /run/current-system/sw/bin/bash /var/tmp/268v-vfio-probe/controller.sh --check
systemd-run --unit=268v-vfio-probe --property=User=root --property=SetLoginEnvironment=yes \
  --property=RuntimeMaxSec=1800 /run/current-system/sw/bin/bash /var/tmp/268v-vfio-probe/controller.sh
```

`User=root` 和 `SetLoginEnvironment=yes` 不能省：交互式 Tailscale SSH 能用，不代表 systemd
的隐式 root 服务有同样的登录环境（第一次就因 `$HOME` 未定义退出）。`--check` 在相同服务
环境里只做预检。其他模式：`--linux`（Linux 诊断客户机）、`--headless`（无软件 VGA）、
`--graphics`（运行 D3D 探针，报告等待 600 秒）、`--interactive`（本机输入，收到报告后
留 10 分钟给人操作，外层 `RuntimeMaxSec=2400`）。

结果在运行控制程序的主机的 `/var/tmp/268v-vfio-probe/`：`controller.log`、`host.txt`、
`start.txt`、`guest.json`、`kernel.log`、`qemu.log`、`screen.png`、`restored.txt`；每轮归档到
`/var/tmp/268v-vfio-probe-<轮次>-<日期>/`（前五轮在 taipan，之后在 tank）。Windows 本地报告在
`C:\IntelDrivers\vfio-report.json`。读结果前不要把“已安排测试”当成直通成功。

### Linux 诊断客户机

`system.build.windowsVMLinuxProbe` 从同一份 Windows domain 定义派生临时 `vfio-linux-probe`，
保留 Q35、OVMF、GPU 地址、ROM、CPU 特征和内存。客户机用宿主同版内核，根目录为 tmpfs，
只读 9p 访问 `/nix/store`，不传入任何磁盘或网卡；`scripts/vfio-probe/linux-guest.sh`
在串口输出 PCI 驱动、DRM 连接器、`drm_info`、`vulkaninfo --summary` 和内核日志后关机。

```sh
nix build --out-link /tmp/268v-linux-probe .#nixosConfigurations.268v.config.system.build.windowsVMLinuxProbe --max-jobs 2 --cores 4
```

产物有 `desktop.xml`（不直通，先验证采集流程）和 `vfio.xml`，只用 `virsh create` 临时启动，
有独立的 NVRAM。串口文件要预先由 root 创建并交给 `qemu-libvirtd`：
`/var/lib/libvirt/qemu/vfio-linux-probe-serial.log`。Vulkan 列出 llvmpipe 不算核显成功，
必须核对 Intel 硬件设备和 `xe` 初始化结果。

### 驱动

`system.build.windowsVMOEMDriver` 下载、校验并打包
[联想 Yoga Slim 7 14ILL10 原厂驱动](https://support.lenovo.com/us/en/downloads/ds573068-intel-vga-driver-for-windows-11-64-bit-yoga-slim-7-14ill10-lenovo-slim-7-14ill10)
（`32.0.101.7026`，INF 明确包含 `PCI\VEN_8086&DEV_64A0&SUBSYS_383E17AA`）。不要套用 11–14 代
核显的 7085 包，版本号接近不能代替硬件 ID 检查。`scripts/vfio-probe/stage-lenovo.ps1`
在 Windows 管理员环境验证 ZIP hash 和 catalog 签名，导出旧驱动备份后预置原厂驱动。
现在跑通的组合用的就是它。

### Direct3D 探针

`system.build.windowsVMD3DProbe` 用 MinGW 交叉编译 `pkgs/vfio-d3d-probe/main.cpp`：按
[D3D11CreateDevice](https://learn.microsoft.com/en-us/windows/win32/api/d3d11/nf-d3d11-d3d11createdevice)
创建硬件设备，核对 DXGI vendor/device 必须为 `8086:64a0`，不回退 WARP；绘制 120 帧
256×256 三角形并逐帧读回核对全部像素。它只验证小型离屏绘制，不能代替游戏负载、
显示扫描输出或长期稳定性测试。`--warp` 只供软件自检。

## 本机键盘与触摸板

`my.windowsVM.localInput` 默认关闭，仅 VFIO specialisation 开启；普通 Linux 桌面不抓取设备。
NixVirt 的 `input type=evdev` 用稳定路径，避免 event 编号跨启动变化：

- 键盘：`/dev/input/by-path/platform-i8042-serio-0-event-kbd`
- 触摸板原始输入：`/dev/input/by-path/pci-0000:00:19.0-platform-i2c_designware.3-event-mouse`
- 交给 QEMU 的触摸板：`/dev/input/vfio-touchpad`，由 `vfio-touchpad.service` 创建

VFIO 模式关闭 `services.keyd`，避免它独占物理键盘。QEMU 把输入转成 PS/2 键盘 / USB mouse，
不需要 Windows 驱动。同时按下再释放左右 Shift 切换抓取（这款键盘没有右 Ctrl）。
没有传入整个 I2C/USB 控制器，也没有把 QEMU 用户加入 input 组。

触摸板不能直接交给 QEMU：input-linux 会把 ABS_X/Y 当绝对坐标（第十二轮“像绝对坐标”）。
`pkgs/vfio-touchpad` 用 [libinput pointer API](https://wayland.freedesktop.org/libinput/doc/latest/api/group__event__pointer.html)
解释触摸板，再用 libevdev/uinput 输出相对位移、按键和滚轮；只有轻触点击和双指滚动，
没有 Precision Touchpad 的多指手势。`scripts/vfio-probe/touchpad-integration.py` 用克隆能力的
模拟设备测试它（需 root、python-evdev，参数是构建出的 `vfio-touchpad` 路径），不抓取真实触摸板。
依据：[QEMU 10.2.4 input-linux](https://github.com/qemu/qemu/blob/v10.2.4/ui/input-linux.c)、
[libvirt input 定义](https://libvirt.org/formatdomain.html#input-devices)。

## 实验记录

| 轮次 | 日期 | 改了什么 | 结果 |
| --- | --- | --- | --- |
| 1 | 10-02 | 首次 VFIO | QEMU 因 `x-igd-legacy-mode` 参数类型拒绝启动（`docs/incidents.md#268v-vfio-qemu-property-type`） |
| 2 | 10-03 | 参数改为字符串 `off` | VM 启动、拿到 DHCP，随后宿主收到短按电源键事件关机，没有 GPU 结果 |
| 3 | 10-03 | Intel `32.0.101.9033` | 驱动绑定但 Code 43（`CM_PROB_FAILED_POST_START`） |
| 4 | 10-04 | GPU 移到根总线 `00:02.0` | 仍 Code 43 |
| 5 | 10-04 | 读客户机固件状态 | ASLS 有效、OpRegion 3.2，ROM 确实执行了；仍 Code 43，DxgKrnl 549 `StartAdapter_DpiFdoEnumChildDevicesFailed` |
| 6 | 10-09 | `hideHypervisor` | 仍 Code 43；扩展 VBT `$VBT LUNARLAKE` 在位（10-04 那次因 VM 没关掉而中止） |
| 7 | 10-09 | Linux 诊断客户机 | `xe` 初始化 `8086:64a0`，eDP-1 connected，Vulkan 枚举出 Intel LNL |
| 8 | 10-09 | 联想原厂 7026 驱动 | 正确绑定，仍 Code 43 |
| 9 | 10-09 | 去掉软件 VGA | **设备 OK**，2880×1800，没有新的 DxgKrnl 549 |
| 10 | 10-09 | D3D 探针 | 120 帧全部像素匹配，feature level 11.1 |
| 11 | 10-09 | 显示器诊断 | Windows 识别内屏 `LEN8AC3`、active、亮度 75%；用户说“好像有输出了”但键盘不能用 |
| 12 | 10-09 | 本机键盘和触摸板 | 键盘可用，触摸板像绝对坐标 |
| 13 | 准备 | libinput 触摸板转换（generation 20） | 未测 |

第九轮支持“软件 VGA 与 Windows 驱动初始化不兼容”，但移除它也改变了 PCI 外设位置；
成功组合仍包含原厂 7026 和基础 CPU 隐藏，没有分别证明这两项是否必需。

一路上误导过的地方：

- 控制流程成功、`systemctl show` 的默认 `Result=success`、预检通过，都不代表 GPU 成功，
  也不代表宿主真的重启过。
- QEMU 的 `vfio_container_dma_map ... -22` 和 BAR peer-to-peer 警告每轮都有，Linux 客户机
  照样初始化成功，不能当作 Code 43 的根因。CPU 和 DMAR 的地址宽度都是 42，没有套用
  “宿主 CPU 位宽大于 IOMMU”的诊断。
- `ASLS+0x400` 的内嵌 VBT 为空不说明缺 VBT：OpRegion 2.1 起按基址加 RVDA 读扩展 VBT。
- PnP 的 “device started” 不代表图形适配器初始化成功；只采集 System 日志会漏掉
  `Microsoft-Windows-DxgKrnl-Admin` 的 549 事件（通道名用连字符）。
- 只请求 `D3D_DRIVER_TYPE_HARDWARE` 在普通 VM 里会拿到 Microsoft Basic Render Driver
  （`1414:008c`），必须核对 DXGI ID。
- “设备 OK + 2880×1800 + 离屏绘制通过”只说明驱动和渲染路径可用：第十轮时内屏其实一直黑。
- `HypervisorPresent=true` 只说明看得到 hypervisor，不说明嵌套 Hyper-V 在跑。

当前 ROM 只有 IgdAssignmentDxe。上游另有 PlatformGopPolicy，配合从主机固件提取的
IntelGopDriver 可提供 GOP 显示初始化
（[VfioIgdPkg 说明](https://github.com/tomitamoeko/VfioIgdPkg/blob/067328df2554c865cc0078cb922357301c4c36c6/README.md)）；
缺 GOP 是否是内屏黑屏的原因没有证据。联想 BIOS 包 QSCN33WW（宿主当前 QSCN13WW）下载校验过，
没有刷写，也没有提取 GOP。

### 相似问题检索（2026-10-04）

没有找到 **268V/140V + Windows 整卡直通成功**的一手实测；项目列表写有 Lunar Lake 支持
不能代替同机验证。

| 一手记录 | 观察与适用边界 |
| --- | --- |
| [NixOS + 14700K/UHD 770，issue 31](https://github.com/LongQT-sea/intel-igpu-passthru/issues/31) | Q35 + UPT，noGOP ROM 解决 Code 43，保留虚拟显示设备且可用 Looking Glass；不是 Lunar Lake。 |
| [8705G/HD 630，issue 39](https://github.com/LongQT-sea/intel-igpu-passthru/issues/39) | i440fx 可用，Q35 + noGOP 仍 Code 43；issue 关闭不等于解决。 |
| [NUC 14 Pro/Meteor Lake 的 ESXi 实测](https://williamlam.com/2024/09/esxi-on-asus-nuc-14-pro-revel-canyon.html) | Linux 客户机可用，Windows 驱动 Code 43；hypervisor 和 GPU 代际均不同。 |
| [Arrow Lake 285K，issue 13](https://github.com/LongQT-sea/intel-igpu-passthru/issues/13) | 黑屏靠较新 Linux 发行版与 noGOP ROM 解决；验证的是 Linux。 |
| [EVE 的实现 PR 5686](https://github.com/lf-edge/eve/pull/5686) | 修正 OpRegion/BDSM 和某些 GCC/LTO 构建问题，测试的是 RPL-P、Alder Lake-N。 |

EVE 提到约 9.6 KiB 的 ROM 可能被 LTO 裁掉初始化函数；本机 ROM 10,240 字节，反汇编确认
fw_cfg OpRegion 读取和 PCI offset `0xfc` 写入都在，第五轮也读到了有效 OpRegion。
[QEMU 10.2.4 文档](https://raw.githubusercontent.com/qemu/qemu/v10.2.4/docs/igd-assign.txt)
说 Windows 需要有效 OpRegion，GOP 不是 OS 驱动初始化的普遍必要条件；Meteor Lake 起经
BAR2 访问 stolen memory，不需要旧式 BDSM。

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
  没有套用其补丁，也没有用它替换 Nixpkgs 的 QEMU。
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

## 基础特征隐藏开关

在 `system.nix` 声明 `my.windowsVM.hideHypervisor = true;`，会关闭 CPU 的
hypervisor 标志、开启 KVM hidden，并去掉显式 Hyper-V enlightenments 与
hypervclock（QEMU 参数 `host,migratable=off,hypervisor=off,kvm=off`）。改变后需正常关闭
客户机并重新应用配置，再启动客户机；不要在 NixVirt 管理的 VM 上长期手工编辑 XML。

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

`windowsVMChecks` 用 libvirt 的 Relax NG schema 验证普通、VFIO、VFIO 加基础隐藏、
移除软件 VGA、以及加入本机输入的五份 XML，同时检查 ROM、固件和 VirtIO 光盘真实存在。
这不代替实际 PCI 设备测试。

这是系统模块，不涉及 Home Manager；`just hm` 不会应用这里的改动。
