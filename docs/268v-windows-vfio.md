# 268V Windows 虚拟机与核显直通

2026-10-02。目标是在 268V 上准备可回退的 KVM / Windows 11 / Arc 140V
整卡直通实验环境。配置、网络、磁盘定义与 ROM 构建均由 Nix 管理。
**第三至第六次测试均确认 Arc 140V 在 Windows 中报 Code 43；核显加速、内屏输出和命运 2 均未成功验证。**

首次重启测试已完成：核显成功绑定 `vfio-pci`，但 QEMU 因
`x-igd-legacy-mode` 参数类型错误拒绝启动 VM；随后自动恢复普通 NixOS / `xe`。
参数已修正为字符串 `off`，构建与 QEMU 属性类型校验已通过。
2026-10-03 已应用到 generation 13，b650 控制服务的只读预检通过；
第二次测试中 QEMU 成功启动，Windows 获得 DHCP 地址，但 03:46:34 宿主
收到短按电源键事件并关机，显卡报告未返回，无法判定驱动接管或内屏输出。
远端恢复控制因此失联并超时；14:33 再次开机后已确认普通系统、`xe` 和桌面恢复。
详见 [排查记录](incidents.md#268v-vfio-qemu-property-type)。

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

第二次测试（2026-10-03）的结果已归档至 b650 的
`/var/tmp/268v-vfio-probe-second-20261003/`，并补取宿主上次启动的完整 journal。
03:45:26 VM 启动，
03:45:41 Windows 获得 `192.168.178.14`，03:46:34 logind 记录
`Power key pressed short` 并开始关机，03:46:41 日志结束。此前每五秒的 SSH
探测持续成功，不能把控制器随后超时误判为 GPU 导致宿主死机。
QEMU 记录了 `vfio_container_dma_map ... Invalid argument` 和不支持 BAR
peer-to-peer 的警告，但尚无证据证明这些警告阻止 Windows 显卡工作。
关机时 libvirt 尝试保存 VFIO VM 状态失败（设备不可迁移）。重试准备中已声明
`libvirtd.onShutdown = "shutdown"`、`shutdownTimeout = 90`，并用
`onBoot = "ignore"` 避免把上次运行状态跨普通/VFIO 启动模式自动恢复。
旧控制器按次数等待叠加 SSH 超时，日志声称的 180 秒实际耗时更长；现改用
经过时间截止值，单次 SSH 15 秒超时后再给 5 秒强制结束，Windows 报告等待
300 秒，最后正在进行的有限时证据采集可能稍微延长这一期限。启动后 30 秒及
其后约每分钟保留一次中间日志和截图，失败读取不会覆盖已保存的成功结果。
预检要求宿主不存在旧 `guest.json`，防止把普通模式验证报告当成新直通结果。

第三次测试准备：上述修复已应用到 generation 14，b650 同环境预检通过。
普通 Windows 的采集任务已成功上传报告，基线另存为 b650 工作目录中的
`baseline-before-third.json`；任务已重新创建，旧 `guest.json` 已归档移开。
基线中的 Arc 140V 是上次直通留下的已断开设备，匹配 Intel `oem9.inf`；
它不能证明本次直通成功，仍需等待实际 VFIO 启动后的报告。

第三次实际结果（2026-10-03）：16:57:55 VM 启动，16:59:13 收到报告，
17:00:25 自动返回普通系统，控制服务 `Result=success`。Arc 140V 正确匹配
Intel `32.0.101.9033` / `oem9.inf`，但 `ConfigManagerErrorCode=43`、
`CM_PROB_FAILED_POST_START`，分辨率为空；软件 VGA 正常。控制流程成功不代表
GPU 成功。报告及截图归档在 b650 `/var/tmp/268v-vfio-probe-third-20261003/`。

第四次对照实验仅改变 GPU 的客户机地址：从自动分配的 `04:00.0` 改为
根总线 `00:02.0`，保持 Q35、软件 VGA、ROM、驱动和 CPU 特征。此布局参照
[QEMU 10.2.4 IGD 文档](https://raw.githubusercontent.com/qemu/qemu/v10.2.4/docs/igd-assign.txt)
及 [上游配置示例](https://github.com/LongQT-sea/intel-igpu-passthru#upt-mode)，
是待验证的兼容性实验，不是已查明的 Code 43 根因。额外采集 Windows
设备 ProblemStatus 和本次开机的系统错误事件。

同次 QEMU 出现对 `0x38190000000` 的 16 MiB DMA 映射失败及 BAR peer-to-peer
警告。CPU 物理地址宽度与所有 DMAR 的 MGAW 实测均为 42，失败地址也在此范围内；
因此没有直接套用“宿主 CPU 比 IOMMU 位宽大”的诊断或盲目降低地址宽度。
当前 ROM 源码对 Lunar Lake 只设置 OpRegion，不分配旧式 stolen memory，
其 OpRegion 路径本身不要求 `00:02.0`；这也是不能提前认定 PCI 位置为根因的原因。

2026-10-04 第四次测试准备完成：PCI 布局配置已激活为 generation 15。
新版采集脚本已在 Windows 以 SYSTEM 身份成功上传普通模式报告，并已重新设置
一次性启动任务。基线在宿主 `/var/tmp/268v-vfio-probe/baseline-before-fourth.json`，
实际测试继续使用 b650 的工作目录。部署前的 sudo 输入超时和 b650 短暂失联均未
触发重启；恢复管理连接后，通过同一已构建闭包的标准激活入口完成切换。

第四次实际结果：02:12:00 VM 启动，02:13:22 收到报告，02:14:30 自动返回普通
系统。Intel 驱动仍为 `32.0.101.9033`，`ProblemCode=43`、`ProblemStatus=0`；
设备实例路径已反映根总线布局。CIM 虽然报告 1280×800，但设备仍为 Error，
不能据此认定核显加速成功。结果已归档至 b650
`/var/tmp/268v-vfio-probe-fourth-20261004/`。

第五次准备保持 generation 15 的系统和 GPU 配置，仅增加 `firmware.py` 只读
采集：从 QEMU 内存布局发现 Q35 ECAM，读取客户机 `00:02.0` 的 PCI 配置、
ASLS 和 OpRegion/VBT 签名。脚本已在普通 VM 的 `00:01.0` 上正确读出
`1234:1111`，控制器同环境预检通过，Windows 一次性任务已重新创建。
此轮用于判断固件初始化是否完成，不是宣称修复 Code 43。

第五次实际结果：15:31:17 VM 启动，15:32:40 收到报告，15:33:54 自动返回普通
系统。驱动仍报 Code 43。客户机 ASLS 为 `0x7bbd2000`，其内存中的
`IntelGraphicsMem` 签名有效，OpRegion 版本 3.2、基础大小 8 KiB；说明 ROM
确实完成了 OpRegion 设置，不能再把“ROM 没执行”当作首要猜测。结果归档在 b650
`/var/tmp/268v-vfio-probe-fifth-20261004/`。

第五次采集的 `vbt_signature_valid=false` 只针对 `ASLS+0x400` 的内嵌 VBT，
**不是完整 VBT 检查结果**。宿主 `xe` debugfs 实测 RVDA=`0x2000`、RVDS=`0x1e00`，
扩展 VBT 为 7,680 字节，签名 `$VBT LUNARLAKE`。依据
[Linux OpRegion 实现](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/i915/display/intel_opregion.c)，
2.1 及以上版本应按 OpRegion 基址加 RVDA 读取扩展 VBT。现已修正脚本，分别
报告 inline/extended 签名，并用宿主真实 OpRegion/VBT 与第五次 PCI 数据回放验证；
客户机扩展 VBT 的实际结果仍待下一轮采集。

恢复后读到了 Windows 保留的四条 DxgKrnl 549 事件，均为
`The request is not supported`，原因 `StartAdapter_DpiFdoEnumChildDevicesFailed`。
PnP 的“device started”事件不代表后续图形适配器初始化成功。此前只采集 System
错误日志遗漏了这些事件；新增读取 `Microsoft-Windows-DxgKrnl-Admin` 和
`Microsoft-Windows-Kernel-PnP/Configuration`。DxgKrnl 日志名使用连字符而非
斜杠，初版查询错误已修正，并让单个通道读取失败不再阻止其他诊断上报。
`Confirm-SecureBootUEFI` 实测为 false，排除未签名 ROM 被 Secure Boot 拦截。

第六次对照配置已构建，并用 `just switch 268v` 激活：普通系统仍保留原 CPU
设置，仅 VFIO specialisation 启用已有的 `my.windowsVM.hideHypervisor`，隐藏
CPUID hypervisor 位及 KVM 标识、移除 Hyper-V enlightenments/clock；GPU 布局、
ROM、驱动、6 vCPU/16 GiB 不变。只使用标准 KVM/libvirt 设置，不修改内核。
[NUC 13 的一手报告](https://forum.proxmox.com/threads/success-asus-intel-nuc-13-pro-i5-1340h-igpu-passthrough-on-proxmox-ve-9.180742/)
把此类 CPU 特征配置列为其 Code 43 修复的一部分，但代际和其他配置不同，不能
据此认定本机根因。第六次应同时检查新事件时间、GPU 状态和扩展 VBT。
准备阶段 b650 曾短暂失联，未在恢复控制链路确认前重启。
最终改用 **tank** 执行第六次控制程序：已确认 tank 可通过 Tailscale SSH
回连 268V。第六次结果应读取 **tank** 的 `/var/tmp/268v-vfio-probe/`；
b650 上保留的第五次结果不能当作本轮结果。控制脚本只允许在 b650 或 tank
运行，仍禁止在会被重启的 268V 本机运行。系统激活为 generation 16，QEMU
转换校验确认 CPU 参数为 `host,migratable=off,hypervisor=off,kvm=off`。

2026-10-09 接续核查：**10 月 4 日安排的第六次实际没有进入 VFIO 测试**。
tank 日志显示 16:07:07 发出 `virsh shutdown` 后，VM 始终未停止；16:09:19
控制程序以 `Guest did not shut down; aborting without reboot` 退出。误导点是
启动前预检和 transient service 启动均成功，但两者都不代表宿主已经重启，
更不能把后续 `systemctl show` 的默认 `Result=success` 当成试验成功。
失败日志已另存 tank `/var/tmp/268v-vfio-probe-sixth-aborted-20261004/`。

10 月 9 日 Windows 控制台仍能正常操作，`VFIOProbe` 任务为 Ready；
`powercfg /QH SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION` 显示 AC/DC 均为 3
（正常关机），并非配置成了忽略电源按钮。没有查明上次 ACPI 请求未完成的原因，
也未修改该电源策略。改从 Windows 管理员命令行执行 `shutdown.exe /s /t 0`，
libvirt 已确认 `shut off (shutdown)`，未强制终止 VM。
本轮继续第六次 CPU 特征对照，启动前先确认 VM 已停止，避免再次卡在同一步。
最新 checkout 的 268V toplevel 与运行中的 generation 16 完全相同，无需重建系统。

第六次实际结果（2026-10-09）：08:52:29 启动 Windows，08:53:52 收到报告，
08:55:33 自动恢复普通系统、`xe` 与桌面。实际 QEMU 日志确认 CPU 参数为
`host,migratable=off,hypervisor=off,kvm=off`，但 Intel `32.0.101.9033` 仍为
Code 43；本次启动新增的 DxgKrnl 549 仍报告
`StartAdapter_DpiFdoEnumChildDevicesFailed` / `The request is not supported`。
因此这组基础隐藏设置未解决本机驱动故障，不能推导需要 CPUID 时序补丁。

本轮客户机 ASLS=`0x7bbd2000`，OpRegion 3.2 签名有效；RVDA=`0x2000`、
RVDS=7,680，客户机 `0x7bbd4000` 处实际读到 `$VBT LUNARLAKE` 扩展 VBT。
内嵌 VBT 为空不构成缺失 VBT 的证据。这里只验证地址、大小和签名，尚未证明
每个显示连接器的数据和驱动兼容。完整结果已归档至 **tank**
`/var/tmp/268v-vfio-probe-sixth-20261009/`。旧 `b650` 现已更名为 `taipan`，
控制程序允许 `taipan|tank`；上文中的 b650 是历史测试时的主机名。

## Linux 客户机对照

`system.build.windowsVMLinuxProbe` 从同一份 Windows domain 定义派生临时
`vfio-linux-probe`，保留 Q35、OVMF、GPU 地址、ROM、CPU 特征和 16 GiB 内存。
客户机使用宿主同版内核，根目录为 tmpfs，通过只读 9p 访问 `/nix/store`；
不传入 Windows 虚拟磁盘、物理磁盘或网卡。NixOS oneshot 服务输出 PCI 驱动、
DRM 连接器、`drm_info`、`vulkaninfo --summary` 和内核日志后自动关机。
Vulkan 列出软件设备不算核显成功，必须核对 Intel 硬件设备和 `xe` 初始化结果。
这用于区分跨客户机的设备问题与 Windows 初始化路径问题，不代表已经验证加速。

```sh
nix build --out-link /tmp/268v-linux-probe .#nixosConfigurations.268v.config.system.build.windowsVMLinuxProbe --max-jobs 2 --cores 4
```

构建产物包含 `desktop.xml`（不直通，用于先验证采集流程）和 `vfio.xml`。
仅显式 `virsh create` 启动临时 VM，不加入 NixVirt 的持久 domain 列表；
它使用独立的 NVRAM。串口文件需预先由 root 创建并交给 `qemu-libvirtd`：
`/var/lib/libvirt/qemu/vfio-linux-probe-serial.log`。
控制程序 `--linux` 模式读取宿主
`/var/tmp/268v-vfio-probe/linux-probe/vfio.xml`，仍先确认 Windows 已关闭，
再经过 VFIO 启动、采集、正常启动恢复流程。`--linux --check` 只做预检。
每轮前归档并清空旧串口日志；Linux 报告完成标记只说明采集完成，不等于 GPU 成功。

2026-10-09 已完成两份 XML schema/QEMU 参数校验，另检查无磁盘、无网卡、
store 只读、GPU 只出现在 VFIO 版、NVRAM 与 Windows 分离。
普通模式实际运行完成 `VFIO_LINUX_PROBE_DONE` 并自动关机；Vulkan 只列出
`llvmpipe`，符合未传入核显的基线。新 `--domain` 参数已从该 VM 的 Q35 ECAM
实际读出软件 VGA `1234:1111`。基线保存在宿主
`/var/tmp/268v-vfio-probe/linux-baseline-20261009.log`。
初次创建时串口路径位于 root-only 目录，QEMU 无法打开；已改为 libvirt 的
QEMU 运行目录并设定文件属主，客户机也禁用串口 getty，避免与诊断输出共用终端。
当前构建产物是 `/nix/store/ipwf2v2xhdk3l8dzr4qgaxj6p49b1yvs-268v-vfio-linux-probe`。
宿主 toplevel 仍与 generation 16 相同，没有执行额外系统切换。
实际核显直通结果须等下一轮 tank 的 `linux-serial.log`，不能用这次基线替代。

## 2026-10-04 相似问题检索

检索了 Lunar Lake、268V、Arc 140V、8086:64a0 与 passthrough / VFIO / Code 43
的组合，并阅读相关仓库 issue 的回复。尚未找到明确记录 **268V/140V + Windows
整卡直通成功**的一手实测；项目列表写有 Lunar Lake 支持不能代替同机验证。

| 一手记录 | 观察与适用边界 |
| --- | --- |
| [NixOS + 14700K/UHD 770，issue 31](https://github.com/LongQT-sea/intel-igpu-passthru/issues/31) | 作者报告 Q35 + UPT，noGOP ROM 解决 Code 43，保留虚拟显示设备且可用 Looking Glass。回复给出 Windows 10 19045.3448、Intel 32.0.101.7085；不是 Lunar Lake。 |
| [8705G/HD 630，issue 39](https://github.com/LongQT-sea/intel-igpu-passthru/issues/39) | 作者报告 i440fx 可用，Q35 + noGOP 仍 Code 43。维护者转向 QEMU 文档，并未提供经验证的修复；issue 关闭不等于解决。 |
| [NUC 14 Pro/Meteor Lake 的 ESXi 实测](https://williamlam.com/2024/09/esxi-on-asus-nuc-14-pro-revel-canyon.html) | Linux 客户机可用，Windows 驱动 Code 43；说明存在相似症状，但 hypervisor 和 GPU 代际均不同。 |
| [Arrow Lake 285K，issue 13](https://github.com/LongQT-sea/intel-igpu-passthru/issues/13) | 黑屏最终通过较新 Linux 发行版与 noGOP ROM 解决；最终回复验证的是 Linux，不能写成 Windows 已成功。 |
| [EVE 的实现 PR 5686](https://github.com/lf-edge/eve/pull/5686) | 作者报告修正 OpRegion/BDSM 和某些 GCC/LTO 构建的问题，测试清单注明 RPL-P、Alder Lake-N；其 Lunar Lake 支持描述缺少本代硬件实测信息。 |

EVE 的补丁描述约 9.6 KiB 的 ROM 可能被 LTO 裁掉初始化函数。本机 ROM 为
10,240 字节，但提取 EFI 后反汇编确认仍有 fw_cfg OpRegion 读取和 PCI offset
`0xfc` 写入的调用序列，不能仅按文件大小套用该补丁。下一步读取实际 ASLS
和内存签名，区分“代码存在”与“固件确实执行成功”。

[QEMU 10.2.4 文档](https://raw.githubusercontent.com/qemu/qemu/v10.2.4/docs/igd-assign.txt)
明确要求 Windows 获得有效 OpRegion，GOP 不是 OS 驱动初始化的普遍必要条件；
Meteor Lake 起通过 BAR2 访问 stolen memory，无需旧式 BDSM 分配。因此继续
排查固件数据交接有依据，尚无证据要求给宿主内核打反检测或时序补丁。

2026-10-02 用户授权实际切换 VFIO。测试工具在 `scripts/vfio-probe/`：
控制程序由 **b650 或 tank 的 root transient systemd service** 运行，不能在 268V 本机运行。
控制程序从当前 system profile 读取 generation，检查普通启动条目与运行中的
system closure 一致，再使用该 generation 的普通与 VFIO 条目。
Windows 的 `VFIOProbe` 一次性启动任务以 SYSTEM 收集显卡及问题设备列表，
向仅监听 VM 网桥的临时接收端提交 JSON，然后自行删除任务。
接收服务有 600 秒运行上限，不开启公共监听，也不自动登录 Windows。

控制程序先正常关闭 VM，使用一次性 VFIO 启动项重启，核实 GPU 已绑定
`vfio-pci` 后启动 VM。拿到 Windows 报告或等待超时后保存日志、控制台截图，
正常请求关闭 VM，再重启返回普通 NixOS。若 Windows 不响应 ACPI 关机，
等待 90 秒后仍会请求宿主重启以恢复桌面；这是首次直通实验的恢复流程。
宿主若失联到无法接收重启命令，则需物理重启；默认启动项一直保留普通 NixOS。

结果保存在运行控制程序的远端主机（前五次 b650，第六次 tank）的
`/var/tmp/268v-vfio-probe/`：`controller.log`、
`host.txt`、`start.txt`、`guest.json`、`kernel.log`、`qemu.log`、`screen.png`、
`restored.txt`。恢复 Codex 后先读取这些文件，不要把“已安排测试”当成直通成功。
宿主本身也保留接收到的 `/var/tmp/268v-vfio-probe/guest.json`；
Windows 本地报告在 `C:\IntelDrivers\vfio-report.json`。
首次失败的完整结果已归档到 b650 的 `/var/tmp/268v-vfio-probe-first-20261002/`，
后续测试使用上面的工作目录。

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
