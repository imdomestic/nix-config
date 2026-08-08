# 告警规则。写成 Nix attrset 再 toJSON —— JSON 是 YAML 的子集,Prometheus
# 直接吃,而且比裸 YAML 字符串多一层求值期的语法检查。
#
# 取舍原则:**宁可漏报也不要误报。** 这些告警最终会进一个四个人的 QQ 群,
# 一条假警报的代价不是"多看一眼",是下一次真警报被当成噪声划过去。所以
# 每条规则的 `for` 都给得比教科书长,阈值也留了余量。
{lib}: let
  # 真实块设备上的文件系统。排除掉伪文件系统,以及 node_exporter 自己就
  # 报错拿不到数的那些(/run/user/* 在非 root 下是 "permission denied",
  # 留着会让磁盘规则算出 0/0)。
  realFs = ''fstype!~"tmpfs|ramfs|overlay|squashfs|iso9660|autofs|fuse.*|nfs.*",device_error=""'';
in
  builtins.toJSON {
    groups = [
      {
        name = "fleet-availability";
        rules = [
          {
            alert = "HostUnreachable";
            expr = ''up{job="node"} == 0'';
            # 10 分钟。r5sjp 跨海、shanghai 在机房,单次抓取失败很常见;
            # 真挂了 10 分钟也不差这一会儿。
            "for" = "10m";
            labels.severity = "critical";
            annotations = {
              summary = "{{ $labels.instance }} 抓不到了";
              description = ''
                Prometheus 已经连续 10 分钟抓不到 {{ $labels.instance }}
                ({{ $labels.arch }})。可能是机器下线、node_exporter 挂了,
                或者 tailscale 断了 —— 这三种现在还分不开,等 maxops-agent
                上线后才能区分(见 docs/maxops.md §7)。
              '';
            };
          }
          {
            # 开机后 10 分钟内一直为真。放 info 级,主要是让群里知道
            # "刚才那台重启过",省得有人对着一段空掉的曲线猜。
            alert = "HostRebooted";
            expr = ''time() - node_boot_time_seconds < 600'';
            labels.severity = "info";
            annotations.summary = "{{ $labels.instance }} 刚重启过";
          }
        ];
      }

      {
        name = "fleet-services";
        rules = [
          {
            # 这条就是"服务运行状态"的落点 —— 靠 node_exporter 的 systemd
            # collector,不需要另做健康检查。
            alert = "SystemdUnitFailed";
            expr = ''node_systemd_unit_state{state="failed"} == 1'';
            "for" = "5m";
            labels.severity = "warning";
            annotations = {
              summary = "{{ $labels.instance }} 上 {{ $labels.name }} 挂了";
              description = "systemctl status {{ $labels.name }} 看详情。";
            };
          }
        ];
      }

      {
        name = "fleet-storage";
        rules = [
          {
            # 只读根文件系统。对 rpi4 这种跑在 SD 卡(/dev/mmcblk1p2)上的
            # 机器,这是最典型的死法 —— 卡坏了内核把 fs 转只读,机器还能
            # ping 通、ssh 还能连,但什么都写不进去,看着像活的。
            # 所以给 critical 而且 for 只有 1 分钟。
            alert = "FilesystemReadOnly";
            expr = ''node_filesystem_readonly{${realFs}} == 1'';
            "for" = "1m";
            labels.severity = "critical";
            annotations = {
              summary = "{{ $labels.instance }} 的 {{ $labels.mountpoint }} 变成只读了";
              description = ''
                设备 {{ $labels.device }}。SD 卡/eMMC 机器上这通常意味着
                存储介质已经出问题,机器看着还活着但写不进去任何东西。
              '';
            };
          }
          {
            alert = "DiskAlmostFull";
            expr = ''node_filesystem_avail_bytes{${realFs}} / node_filesystem_size_bytes{${realFs}} < 0.05'';
            "for" = "15m";
            labels.severity = "critical";
            annotations.summary = "{{ $labels.instance }} 的 {{ $labels.mountpoint }} 剩不到 5%";
          }
          {
            # 趋势告警:按过去 6 小时的斜率外推,24 小时内会写满。
            # 后半段的 < 0.2 是防误报 —— 一个刚被清空又开始写的大盘会算出
            # 很陡的斜率,但它还剩 80% 空间,不该在半夜叫人。
            alert = "DiskWillFillIn24h";
            expr = ''
              predict_linear(node_filesystem_avail_bytes{${realFs}}[6h], 24 * 3600) < 0
              and
              node_filesystem_avail_bytes{${realFs}} / node_filesystem_size_bytes{${realFs}} < 0.2
            '';
            "for" = "1h";
            labels.severity = "warning";
            annotations.summary = "{{ $labels.instance }} 的 {{ $labels.mountpoint }} 按当前速度 24 小时内写满";
          }
        ];
      }

      {
        name = "fleet-memory";
        rules = [
          {
            # 2026-08-07 h610 那次(15 GiB 无 swap,nix flake check 打满内存,
            # 机器长时间无响应)之后加的。MemAvailable 比 MemFree 准 ——
            # 它算进了可回收的页缓存。
            alert = "MemoryPressureHigh";
            expr = ''node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes < 0.1'';
            "for" = "15m";
            labels.severity = "warning";
            annotations = {
              summary = "{{ $labels.instance }} 可用内存不到 10%";
              description = "持续 15 分钟。检查有没有 swap/zram,以及是不是有构建在跑。";
            };
          }
          {
            # OOM 杀已经发生过了 —— 这是事后通知,不是预警。但很重要:
            # 被杀掉的进程往往悄无声息,不看这个指标根本不知道发生过。
            alert = "OOMKillOccurred";
            expr = ''increase(node_vmstat_oom_kill[30m]) > 0'';
            labels.severity = "warning";
            annotations = {
              summary = "{{ $labels.instance }} 过去 30 分钟发生了 OOM 杀进程";
              description = "journalctl -k | grep -i 'killed process' 看被杀的是谁。";
            };
          }
        ];
      }

      {
        name = "fleet-hardware";
        rules = [
          {
            # ARM 小机器(rpi4/r5s/r6s/r2s)基本都是被动散热,夏天会降频甚至
            # 关机。80°C 是降频区间的入口,还没到危险,但值得知道。
            alert = "HighTemperature";
            expr = ''node_hwmon_temp_celsius > 80'';
            "for" = "10m";
            labels.severity = "warning";
            annotations.summary = "{{ $labels.instance }} 温度 {{ $value | printf \"%.0f\" }}°C({{ $labels.chip }})";
          }
          {
            # 时钟漂移会连锁搞坏 TLS 证书校验、wireguard 的重放窗口和
            # tailscale 的握手 —— 而这些的报错信息通常完全不指向时间。
            # 0.5 秒远没到出问题的程度,但足以说明 NTP 没在工作。
            alert = "ClockSkew";
            expr = ''abs(node_timex_offset_seconds) > 0.5'';
            "for" = "15m";
            labels.severity = "warning";
            annotations.summary = "{{ $labels.instance }} 时钟偏了 {{ $value | printf \"%.2f\" }}s,检查 NTP";
          }
        ];
      }

      {
        name = "monitoring-self";
        rules = [
          {
            # 监控系统自己坏了是最隐蔽的故障:所有面板一片绿,因为根本没在
            # 采数。这条是那个盲区的唯一出口。
            alert = "PrometheusSelfScrapeFailing";
            expr = ''up{job="prometheus"} == 0'';
            "for" = "5m";
            labels.severity = "critical";
            annotations.summary = "Prometheus 抓不到自己 —— 监控可能整个不可信了";
          }
          {
            alert = "PrometheusRuleEvaluationFailing";
            expr = ''increase(prometheus_rule_evaluation_failures_total[15m]) > 0'';
            labels.severity = "warning";
            annotations.summary = "Prometheus 有告警规则求值失败,可能有规则写错了";
          }
        ];
      }
    ];
  }
