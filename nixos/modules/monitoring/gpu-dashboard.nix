let
  datasource = {
    type = "prometheus";
    uid = "$datasource";
  };
  select = ''instance=~"$host",uuid=~"$gpu"'';
  metric = name: "${name}{${select}}";
  detail = field: ''nvidia_gpu_detail_value{${select},field=~"${field}"}'';
  target = expr: legend: {
    inherit expr;
    legendFormat = legend;
    refId = "A";
  };
  panel = id: title: unit: expr: {
    inherit id title datasource;
    type = "timeseries";
    gridPos = {
      x = 0;
      y = 0;
      w = 12;
      h = 8;
    };
    targets = [(target expr "{{instance}} {{uuid}} {{__name__}} {{field}} {{engine}} {{pid}} {{fan}}")];
    fieldConfig = {
      defaults = {
        inherit unit;
        custom = {
          drawStyle = "line";
          lineWidth = 1;
          fillOpacity = 8;
          spanNulls = false;
        };
      };
      overrides = [];
    };
    options = {
      legend = {
        displayMode = "table";
        placement = "bottom";
        calcs = ["lastNotNull" "mean" "max"];
      };
      tooltip.mode = "multi";
    };
  };
  stat = id: title: unit: expr:
    (panel id title unit expr)
    // {
      type = "stat";
      gridPos = {
        x = (id - 1) * 4;
        y = 0;
        w = 4;
        h = 4;
      };
      options = {
        reduceOptions = {
          calcs = ["lastNotNull"];
          values = false;
        };
        colorMode = "value";
        graphMode = "area";
      };
    };
  table = id: title: expr:
    (panel id title "short" expr)
    // {
      type = "table";
      targets = [
        {
          inherit expr;
          refId = "A";
          instant = true;
          format = "table";
        }
      ];
      options = {
        showHeader = true;
        cellHeight = "sm";
      };
      fieldConfig = {
        defaults.custom.filterable = true;
        overrides = [];
      };
    };
  row = id: title: {
    inherit id title;
    type = "row";
    collapsed = false;
    panels = [];
    gridPos = {
      x = 0;
      y = id * 4;
      w = 24;
      h = 1;
    };
  };
  queryVariable = name: label: query: {
    inherit name label datasource query;
    type = "query";
    refresh = 1;
    multi = true;
    includeAll = true;
    allValue = ".*";
    current = {
      text = "All";
      value = "$__all";
    };
  };
  layout = panels:
    (builtins.foldl' (acc: p:
        if p.id < 9
        then acc // {panels = acc.panels ++ [p];}
        else if p.type == "row"
        then let
          y =
            acc.y
            + (
              if acc.x == 12
              then 8
              else 0
            );
        in {
          panels =
            acc.panels
            ++ [
              (p
                // {
                  gridPos = {
                    x = 0;
                    inherit y;
                    w = 24;
                    h = 1;
                  };
                })
            ];
          y = y + 1;
          x = 0;
        }
        else {
          panels =
            acc.panels
            ++ [
              (p
                // {
                  gridPos = {
                    inherit (acc) x y;
                    w = 12;
                    h = 8;
                  };
                })
            ];
          y =
            acc.y
            + (
              if acc.x == 12
              then 8
              else 0
            );
          x =
            if acc.x == 0
            then 12
            else 0;
        }) {
        panels = [];
        x = 0;
        y = 13;
      }
      panels).panels;
in {
  uid = "fleet-gpu";
  title = "GPU · NVIDIA 全量监控";
  description = "主机登记驱动的 GPU 监控。N/A 和空图代表不支持或未采到，不等于 0。均值/峰值分别显示。";
  tags = ["fleet" "gpu" "nvidia" "nix"];
  schemaVersion = 39;
  version = 1;
  editable = false;
  timezone = "browser";
  refresh = "15s";
  time = {
    from = "now-6h";
    to = "now";
  };
  templating.list = [
    {
      name = "datasource";
      label = "Prometheus";
      type = "datasource";
      query = "prometheus";
      current = {
        text = "Prometheus";
        value = "prometheus";
      };
    }
    (queryVariable "host" "主机" ''label_values(up{job="nvidia-gpu"}, instance)'')
    (queryVariable "gpu" "GPU UUID" ''label_values(nvidia_smi_gpu_info{instance=~"$host"}, uuid)'')
    (queryVariable "raw_metric" "原生指标检索" ''label_values({__name__=~"nvidia_smi_.+",instance=~"$host"}, __name__)'')
  ];
  annotations.list = [
    {
      name = "GPU alerts";
      enable = true;
      inherit datasource;
      expr = ''ALERTS{component="gpu",alertstate="firing",instance=~"$host"}'';
      titleFormat = "{{alertname}}";
      textFormat = "{{instance}} {{uuid}}";
      tagKeys = "severity";
    }
  ];
  panels = layout [
    (stat 1 "GPU 利用率" "percentunit" (metric "nvidia_smi_utilization_gpu_ratio"))
    (stat 2 "显存余量" "bytes" (metric "nvidia_smi_memory_free_bytes"))
    (stat 3 "GPU 温度" "celsius" (metric "nvidia_smi_temperature_gpu"))
    (stat 4 "平均功耗" "watt" (metric "nvidia_smi_power_draw_average_watts"))
    (stat 5 "GPU exporter" "bool" ''up{job="nvidia-gpu",instance=~"$host"}'')
    (stat 6 "详细数据距今" "s" ''time() - nvidia_gpu_collection_timestamp_seconds{instance=~"$host"}'')
    ((table 7 "设备清单 / 驱动 / CUDA / PCIe 地址" (metric "nvidia_gpu_device_info"))
      // {
        gridPos = {
          x = 0;
          y = 4;
          w = 24;
          h = 5;
        };
      })
    ((panel 8 "采集范围与解读" "short" "")
      // {
        type = "text";
        targets = [];
        gridPos = {
          x = 0;
          y = 9;
          w = 24;
          h = 4;
        };
        options = {
          mode = "markdown";
          content = ''
            原生 query-gpu 自动发现字段；详细采集补充 XML、逐进程 pmon、NVML 能耗与内核 Xid。采样约 15 秒。
            **N/A、空图是不可用，不是零。** 下方能力表可区分硬件不支持与采集失败。能耗仅展示驱动真实计数器。
            模型常驻显存和达到正常功耗上限不会单独报警；显存只按持续绝对余量报警。空闲 PCIe 降速是正常节能。
          '';
        };
      })
    (row 9 "计算 / 显存 / 视频引擎")
    (panel 10 "GPU 与显存控制器利用率" "percentunit" ''{__name__=~"nvidia_smi_utilization_(gpu|memory)_ratio",${select}}'')
    (panel 11 "VRAM：已用 / 空闲 / 保留 / 总量" "bytes" ''{__name__=~"nvidia_smi_memory_(used|free|reserved|total)_bytes",${select}}'')
    (panel 12 "编码 / 解码 / JPEG / OFA" "percentunit" ''{__name__=~"nvidia_smi_utilization_(encoder|decoder|jpeg|ofa)_ratio",${select}}'')
    (panel 13 "BAR1 映射窗口" "bytes" (detail "bar1_memory_usage/.*"))
    (panel 14 "编码 / FBC 会话数量与 FPS" "short" (detail "(encoder_stats|fbc_stats)/(session_count|average_fps)"))
    (panel 15 "编码 / FBC 平均延迟（驱动原始值）" "short" (detail "(encoder_stats|fbc_stats)/average_latency"))
    (row 16 "温度 / 散热 / 功耗 / 能耗")
    (panel 17 "GPU / 显存温度" "celsius" (detail "temperature/(gpu_temp|memory_temp)"))
    (panel 18 "T.Limit 温度余量及边界" "celsius" (detail "temperature/.*tlimit.*"))
    (panel 19 "风扇转速百分比" "percentunit" (metric "nvidia_smi_fan_speed_ratio"))
    (panel 53 "逐风扇转速百分比" "percentunit" (metric "nvidia_gpu_fan_speed_ratio"))
    ((panel 54 "逐风扇目标 RPM" "rotrpm" (metric "nvidia_gpu_fan_intended_speed_rpm"))
      // {
        description = "NVML 报告的是驱动预期转速，不能据此判断风扇是否被物理卡住。";
      })
    (panel 20 "瞬时 / 平均 / 上限功耗" "watt" (detail "gpu_power_readings/(average_power_draw|instant_power_draw|current_power_limit)"))
    (panel 21 "显存 / 模组功耗（硬件支持时）" "watt" (detail "(gpu_memory_power_readings|module_power_readings)/.*"))
    (panel 22 "真实累计能耗变化 · 1 小时" "joule" ''increase(${metric "nvidia_gpu_energy_joules_total"}[1h])'')
    (row 23 "频率 / 性能状态 / 降频")
    (panel 24 "Graphics / SM / Memory / Video 频率" "hertz" (detail "clocks/.*"))
    (panel 25 "最大频率" "hertz" (detail "max_clocks/.*"))
    (panel 26 "性能状态 P0–P15（越小越高）" "short" (metric "nvidia_smi_pstate"))
    (panel 27 "全部降频原因（1 = 活跃）" "bool" (detail "clocks_event_reasons/.*"))
    (panel 28 "各降频原因累计时间" "s" (detail "clocks_event_reasons_counters/.*"))
    (panel 29 "过去 5 分钟热 / 功耗降频占比" "percentunit" ''rate({__name__=~"nvidia_smi_clocks_event_reasons_counters_.*_seconds",${select}}[5m])'')
    (row 30 "PCIe / 可靠性 / 驱动错误")
    (panel 31 "PCIe TX / RX 吞吐" "Bps" (detail "pci/(tx_util|rx_util)"))
    (panel 32 "PCIe 当前 / 最大代数" "short" (detail "pci/pci_gpu_link_info/pcie_gen/.*"))
    (panel 33 "PCIe 当前 / 最大宽度" "short" (detail "pci/pci_gpu_link_info/link_widths/.*"))
    (panel 34 "PCIe 重放 / 回卷计数" "short" (detail "pci/replay.*counter"))
    (panel 35 "ECC 错误（支持时）" "short" (detail "ecc_errors/(volatile|aggregate)/.*"))
    (panel 36 "页退役 / 行重映射 / 待修复" "short" (detail "retired_pages/.*|remapped_rows/.*|ecc_errors/.*repair.*"))
    (table 37 "Xid 计数（本次开机观察到）" (metric "nvidia_gpu_xid_errors_total"))
    (table 38 "Xid 最近发生时间" (metric "nvidia_gpu_xid_last_timestamp_seconds"))
    (row 39 "逐进程占用（PID 变化会产生新序列）")
    (panel 40 "各进程显存" "bytes" (metric "nvidia_gpu_process_memory_bytes"))
    (panel 41 "各进程 SM / 显存 / 视频引擎利用率" "percentunit" (metric "nvidia_gpu_process_utilization_ratio"))
    (table 42 "进程清单 / 计算实例" (metric "nvidia_gpu_process_info"))
    (panel 43 "GPU 进程数量" "short" (metric "nvidia_gpu_processes"))
    (row 44 "采集健康 / 全字段检索")
    (panel 45 "XML / pmon / NVML / journal 采集成功" "bool" ''nvidia_gpu_collector_success{instance=~"$host"}'')
    (panel 46 "详细采集耗时" "s" ''nvidia_gpu_collection_duration_seconds{instance=~"$host"}'')
    (table 47 "不可用 / 不支持 / 已废弃字段" ''nvidia_gpu_field_available{${select}} == 0'')
    (table 48 "全部可用数值（field / unit）" (metric "nvidia_gpu_detail_value"))
    (table 49 "设备属性 / 枚举状态 / 固件" (metric "nvidia_gpu_field_info"))
    (table 50 "原生 exporter 全量指标（用顶部检索器过滤）" ''{__name__=~"$raw_metric",${select}}'')
    (table 51 "当前 GPU 告警" ''ALERTS{component="gpu",instance=~"$host"}'')
    (table 52 "各显存频率档支持的 Graphics 频率范围" ''{__name__=~"nvidia_gpu_supported_graphics_clocks_.*",${select}}'')
  ];
}
