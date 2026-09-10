{
  lib,
  gpuHosts,
  dashboardUrl,
}: let
  alert = name: expr: duration: severity: summary: description: {
    alert = name;
    inherit expr;
    "for" = duration;
    labels = {
      inherit severity;
      component = "gpu";
    };
    annotations = {
      inherit summary description;
      dashboard_url = "${dashboardUrl}/d/fleet-gpu?var-host={{ $labels.instance }}&var-gpu={{ $labels.uuid }}";
    };
  };
in {
  groups = [
    {
      name = "gpu";
      interval = "15s";
      rules =
        (lib.concatMap (host:
          map (uuid: {
            record = "nvidia_gpu_inventory_expected";
            expr = "vector(1)";
            labels = {
              instance = host.name;
              uuid = lib.toLower (lib.removePrefix "GPU-" uuid);
            };
          })
          host.gpuMonitoring.uuids)
        gpuHosts)
        ++ [
          (alert "GPUExporterDown" ''up{job="nvidia-gpu"} == 0'' "3m" "warning"
            "{{ $labels.instance }} GPU exporter 无法抓取"
            "检查 prometheus-nvidia-gpu-exporter、驱动和 Tailnet 9835 端口。")
          (alert "GPUCollectionFailed" ''
              nvidia_smi_command_exit_code != 0
              or (up{job="nvidia-gpu"} == 1 unless on(instance) nvidia_smi_gpu_info)
            '' "3m" "warning"
            "{{ $labels.instance }} exporter 在线但没有有效 GPU 数据"
            "HTTP 成功不代表 nvidia-smi 采集成功；检查驱动、设备和 exporter 日志。")
          (alert "GPUDeviceMissing" ''
              (nvidia_gpu_inventory_expected unless on(instance, uuid) nvidia_smi_gpu_info)
              and on(instance) (up{job="nvidia-gpu"} == 1)
            '' "5m" "critical"
            "{{ $labels.instance }} 预期 GPU {{ $labels.uuid }} 消失"
            "登记的 UUID 未被采集到。检查 nvidia-smi -L、PCIe 和内核 Xid；换卡后更新主机登记。")
          (alert "GPUDetailCollectionStale" ''
              (time() - nvidia_gpu_collection_timestamp_seconds > 90)
              or (up{job="nvidia-gpu"} == 1 unless on(instance) nvidia_gpu_collection_timestamp_seconds)
            '' "3m" "warning"
            "{{ $labels.instance }} GPU 详细采集停止更新"
            "检查 gpu-detail-metrics.timer/service 及 node exporter textfile collector；旧文件不能代表当前状态。")
          (alert "GPUDetailCollectorFailed" ''nvidia_gpu_collector_success == 0'' "5m" "warning"
            "{{ $labels.instance }} GPU {{ $labels.collector }} 采集失败"
            "部分详细指标缺失；查看 journalctl -u gpu-detail-metrics。N/A 不会触发此告警。")
          (alert "GPUTemperatureHigh" ''
              nvidia_smi_temperature_gpu > on(instance, uuid) nvidia_gpu_temperature_warning_celsius
            '' "10m" "warning"
            "{{ $labels.instance }} GPU {{ $labels.uuid }} 持续高温 {{ $value }}°C"
            "检查风扇、进风、机箱散热和负载；阈值由 my.telemetry.gpu 配置。")
          (alert "GPUTemperatureCritical" ''
              nvidia_smi_temperature_gpu > on(instance, uuid) nvidia_gpu_temperature_critical_celsius
            '' "2m" "critical"
            "{{ $labels.instance }} GPU {{ $labels.uuid }} 危险高温 {{ $value }}°C"
            "优先检查散热和温度余量，人工决定是否降低负载。")
          (alert "GPUThermalThrottling" ''
              max by(instance, uuid) ({__name__=~"nvidia_smi_clocks_event_reasons_(hw_thermal_slowdown|sw_thermal_slowdown)"}) > 0
            '' "3m" "warning"
            "{{ $labels.instance }} GPU {{ $labels.uuid }} 持续热降频"
            "驱动明确报告热降频；正常的 SW power cap 和空闲降频不在告警范围。")
          (alert "GPUPowerBrake" ''nvidia_smi_clocks_event_reasons_hw_power_brake_slowdown > 0'' "3m" "warning"
            "{{ $labels.instance }} GPU {{ $labels.uuid }} 硬件供电降频"
            "检查供电、连接器及电源余量；这与正常达到功耗上限不同。")
          (alert "GPUMemoryHeadroomLow" ''
              nvidia_smi_memory_free_bytes < on(instance, uuid) (nvidia_gpu_memory_free_warning_bytes > 0)
            '' "15m" "warning"
            "{{ $labels.instance }} GPU {{ $labels.uuid }} 显存余量仅 {{ $value | humanize1024 }}B"
            "这是持续容量压力，不等于已经 OOM。检查逐进程占用与模型预算；可按主机调整或用 0 关闭。")
          (alert "GPUPCIeReplayErrors" ''
              delta(nvidia_gpu_detail_value{field="pci/replay_counter"}[10m]) > 100
            '' "5m" "warning"
            "{{ $labels.instance }} GPU {{ $labels.uuid }} PCIe 重放持续增加"
            "检查 PCIe 链路、插槽和供电；计数器复位下降不触发告警。")
          (alert "GPUUncorrectableECC" ''
              nvidia_gpu_detail_value{field=~"ecc_errors/(volatile|aggregate)/.*uncorrectable.*"} > 0
            '' "1m" "critical"
            "{{ $labels.instance }} GPU {{ $labels.uuid }} 不可纠正 ECC 错误"
            "检查 ECC 详情和 NVIDIA 恢复建议；不支持 ECC 的卡不会生成零值。")
          (alert "GPUMemoryRepairPending" ''
              nvidia_gpu_detail_value{field=~"ecc_errors/(channel_repair_pending|tpc_repair_pending)|retired_pages/pending_(blacklist|retirement)|remapped_rows/(pending|failure)"} > 0
            '' "5m" "warning"
            "{{ $labels.instance }} GPU {{ $labels.uuid }} 显存修复待处理或失败"
            "检查驱动报告的 page retirement、row remap 和修复状态，维护操作需单独安排。")
          (alert "GPURecoveryRequired" ''
              nvidia_gpu_field_info{field="gpu_recovery_action",value!="None"} == 1
            '' "2m" "critical"
            "{{ $labels.instance }} GPU {{ $labels.uuid }} 驱动要求恢复操作"
            "驱动报告 {{ $labels.value }}；先保存现场和日志，再按 NVIDIA 文档处理。")
          (alert "GPUXidError" ''
              time() - nvidia_gpu_xid_last_timestamp_seconds{code!~"63|92|79|48|94|95"} < 600
            '' "0m" "warning"
            "{{ $labels.instance }} GPU {{ $labels.uuid }} 新 Xid {{ $labels.code }}"
            "这是驱动事件，不自动归因于硬件损坏；结合应用和内核日志分析。63/92 仅在看板记录。")
          (alert "GPUXidCritical" ''
              time() - nvidia_gpu_xid_last_timestamp_seconds{code=~"79|48|94|95"} < 600
            '' "0m" "critical"
            "{{ $labels.instance }} GPU {{ $labels.uuid }} 严重 Xid {{ $labels.code }}"
            "包含掉总线或不可纠正显存错误；检查内核日志及 NVIDIA Xid 恢复建议。")
        ];
    }
  ];
}
