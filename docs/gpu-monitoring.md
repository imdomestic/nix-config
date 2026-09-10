# GPU 监控

## 启用和扩展

在 `nixos/hosts/<host>/default.nix` 登记，采集端和所有 monitor 的抓取目标共用此信息：

```nix
tsIp = "100.64.0.33";
gpuMonitoring = {
  enable = true;
  uuids = ["GPU-d8ec4dea-3771-68e6-9f8b-11811e47ac9d"];
};
```

UUID 用 `nvidia-smi -L` 获取。空列表自动纳入该机全部 NVIDIA GPU；显式列表只保留选中卡，
并额外检查这些卡是否消失。换卡要更新 UUID；加卡向列表追加。主机必须运行原生 NVIDIA
驱动且启用 telemetry。目前后端支持 NVIDIA；AMD/Intel 需要新增对应采集后端，不能只填 UUID。

修改后求值并部署 GPU 主机以及 `roles` 含 `monitor` 的主机，目前为 h610、tank。
使用 `just deploy-system <host>`；从 macOS 调用 deploy-rs 须加 `--remote-build`。
Home Manager 与此无关。Grafana 看板、选择器和告警目标自动跟随登记，无须手动导入。

GPU 主机可在 `system.nix` 通过原生自定义模块选项覆盖阈值：

```nix
my.telemetry.gpu = {
  temperatureWarning = 83;
  temperatureCritical = 88;
  memoryFreeWarningMiB = 128; # 0 关闭容量预警
};
```

## 采集内容和边界

| 来源 | 数据 | 周期 / 出口 |
|---|---|---|
| NixOS `services.prometheus.exporters.nvidia-gpu` | 驱动自动发现的全部 query-gpu 字段；GPU/显存/视频引擎利用率、FB 显存、温度、风扇、功耗/上限、频率/P-state、降频原因/时间、ECC 等 | 两份 Prometheus 各 15 秒抓取，Tailnet IP:9835 |
| `nvidia-smi -q -x` | 全部可用数值和属性：BAR1、PCIe TX/RX/重放、温度余量/边界、修复状态、固件/恢复动作、GPU/MIG/计算实例进程占用等 | 15 秒 oneshot，原子写 node exporter textfile；GPU 主机 node 抓取 15 秒 |
| `nvidia-smi pmon -s um -c 1` | 逐 PID 的 SM、显存控制器、编码/解码/JPEG/OFA 利用率（驱动支持时） | 同上 |
| NVML | 驱动累计能耗，mJ 转 J，随驱动重置；逐风扇百分比和目标 RPM（非物理转速反馈） | 同上 |
| 当前启动的内核 journal | Xid 按 GPU UUID、错误码计数及最近时间，持久化游标增量读取 | 同上 |

通用明细以 `nvidia_gpu_detail_value{uuid,field,unit}` 保存，统一字节、秒、赫兹、瓦、摄氏度、
比例单位。枚举与字符串保存为 `nvidia_gpu_field_info`；每个 XML 字段都同时有
`nvidia_gpu_field_available`。驱动新增字段可直接出现，无须手工维护白名单。
不支持、N/A、已废弃的字段只标记不可用，不生成假的零读数。

静态合法频率目录按每个显存频率档保存 graphics 频率数量、最小和最大值，
避免把数千个从不变化的合法频率枚举变成时序。进程保存 PID、程序 basename 和实例 ID，
不采集命令行参数；进程退出后下一份快照移除其样本。PID 周转会增加历史序列数。
不运行会改变负载的诊断、压力测试或 profiling，不启用 accounting、改功率限制或复位显卡。

XML 失败会移除上一轮设备数值，写入失败标志。进程/能耗/journal 各有独立成功标志。
整个定时器停止时，时间戳过期告警可识别仍被 node exporter 读取的旧文件。
Xid 首次启动仅回看当前开机最近 5 分钟，之后依游标增量读取；重启清零观察计数。
它不是驱动安装以来的完整历史。GPU 掉总线后仍可用持久化 PCI 地址映射归属 Xid。

## 看板与告警

看板 UID `fleet-gpu`，统一入口：
<http://100.64.0.13:3000/d/fleet-gpu>。可选择 Prometheus 副本、主机、GPU 与原生指标名。
包括概览、计算/显存、温度/功率/能耗、频率/降频、PCIe/可靠性、进程、能力和全字段检索。
图例同时显示末值、均值、峰值，不把峰值当平均。

告警包括 exporter 失联、有效数据缺失、登记 GPU 消失、明细陈旧/部分失败、持续高温/危险高温、
热降频/硬件供电降频、显存余量不足、持续 PCIe 重放、不可纠正 ECC、待修复/恢复要求及新 Xid。
单纯高利用率、模型常驻导致显存占用高、空闲 PCIe 降速和 SW power cap 不报警。
Xid 63/92 只记录；79/48/94/95 critical，其余新 Xid warning，具体原因仍须结合日志判断。

规则带 `component=gpu`、主机和 UUID 标签，接入两份 Prometheus 已有的 Alertmanager 集群和
现有 Maxops/default 接收器。critical 温度抑制同卡 warning；既有 HostUnreachable 抑制保留。
无自动调频、杀进程、重启或复位动作。验证测试通过 promtool 完成，不发送伪造告警到群。

## 验证

```sh
python3 scripts/check-gpu-monitoring.py
nix eval --raw .#nixosConfigurations.b650.config.system.build.toplevel.drvPath
nix eval --raw .#nixosConfigurations.h610.config.system.build.toplevel.drvPath
nix eval --raw .#nixosConfigurations.tank.config.system.build.toplevel.drvPath
```

可将 `gpu-alerts.nix` 求值结果传给 `check-gpu-monitoring.py --rules <rules.json>
--promtool-tests <tests.json>`，再执行 `promtool check rules` 和 `promtool test rules`。
上线后检查两份 Prometheus 的 targets/rules API、所有采集 success、最新时间戳、
GPU UUID 和 `nvidia-smi` 的一致性，以及 Grafana provisioning 与 Alertmanager 配置。

上游参考：[nvidia_gpu_exporter](https://github.com/utkuozdemir/nvidia_gpu_exporter)、
[NVIDIA SMI](https://docs.nvidia.com/deploy/nvidia-smi/index.html)、
[NVML energy API](https://docs.nvidia.com/deploy/nvml-api/group__nvmlDeviceQueries.html)、
[Xid 错误](https://docs.nvidia.com/deploy/xid-errors/index.html)。
