# 告警规则。写成 Nix attrset 再 toJSON —— JSON 是 YAML 的子集,Prometheus
# 直接吃,而且比裸 YAML 字符串多一层求值期的语法检查。
#
# 取舍原则:**宁可漏报也不要误报。** 这些告警最终会进一个四个人的 QQ 群,
# 一条假警报的代价不是"多看一眼",是下一次真警报被当成噪声划过去。所以
# 每条规则的 `for` 都给得比教科书长,阈值也留了余量。
{
  lib,
  # 这个 fleet 里跑着几份监控(roles 里有 "monitor" 的台数)。用来判断
  # Alertmanager 集群是不是缺人 —— 没有这个数就只能写死一个 2,那样以后
  # 加第三份监控时这条规则会静默地一直不触发。
  monitorCount ? 1,
}: let
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
          {
            # **SD 卡没有健康指标可读**(eMMC 有 life_time / pre_eol,SD 卡
            # 什么都不暴露),累计写入量是唯一能拿到的磨损替代指标。所以这条盯
            # 的是**速率异常**而不是绝对寿命 —— 写入量突然翻几倍意味着有东西
            # 在失控地写,那才是会提前烧掉卡的情形。
            #
            # 40 GB/天 = 全 fleet 稳态最高值的 4 倍;窗口取 24h 而不是 6h 是
            # 拿真实数据试出来的(6h 窗口下一次 rsync 就会误报)。两个数字的
            # 完整推导见 docs/incidents.md#sd-card-write-threshold。
            alert = "FlashWriteRateHigh";
            expr = ''rate(node_disk_written_bytes_total{device=~"mmcblk[0-9]"}[24h]) * 86400 / 1e9 > 40'';
            "for" = "6h";
            labels.severity = "warning";
            annotations = {
              summary = "{{ $labels.instance }} 的 {{ $labels.device }} 写入速率持续偏高";
              description = ''
                过去 6 小时折算 {{ $value | printf "%.1f" }} GB/天,持续了 6 小时。
                这类板子的闪存(SD/eMMC)按写入量磨损,而 SD 卡坏之前不会有任何征兆。
                先看是谁在写:`for p in /proc/[0-9]*; do awk "/^write_bytes/{print \$2}"
                $p/io; done` 排序,或者直接查 journald —— 历史上就是它
                (mihomo info 级日志 49 万行/天,放大成 19.7 GB/天的落盘)。
              '';
            };
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
        name = "tailnet-mesh";
        rules = [
          {
            # **这条是整层的意义所在。** 一对本来直连的机器改走 DERP 中继了。
            #
            # 为什么重要:实测这个 fleet 的直连全部走 IPv6
            # (`[2409:...]:41641` 这种)。IPv6 一断 —— PPPoE 重拨、前缀变更、
            # 运营商调整 —— 链路会**静默**回落到经 h610 的 DERP。延迟上一个
            # 台阶,而且流量开始全部过 h610 的家宽上行。
            #
            # 对 r5sjp 尤其要命:它是唯一出口,直连已经 177ms,降级成
            # DERP-经-国内会再翻一倍,整条代理链跟着一起烂。
            #
            # 只在 active 时判定 —— 空闲链路的 CurAddr 是空的,那是"不知道"
            # 不是"在走中继"。tailscale_peer_direct 本身就只在 active 时才
            # 输出,这里的 and 是双保险。
            alert = "TailscalePathDegraded";
            #
            # 三个条件缺一不可。`online == 1` 是实测补上的:r2s 离线时,其余
            # 七台指向它的链路全部报 active=1 + direct=0(tailscale 在尝试连,
            # 但连不上自然没有直连路径),于是七条链路一起满足前两个条件。
            # 但"到一台关机的机器没有直连"不是路径问题,是那台机器关着 ——
            # 那件事 HostUnreachable 已经在报了。少了这行,fleet 里每关一台
            # 机器就会多出 N-1 条假的降级告警。
            #
            # **`kind="server"` 也不能少。** 同一批指标现在覆盖整个 tailnet,
            # 包括二十来台手机和别人的笔记本。那些设备在蜂窝网、酒店 WiFi、
            # 对称 NAT 后面走中继是完全正常的日常状态,不是需要有人处理的事件。
            # 不加这个过滤,这条告警会天天响,然后所有人开始无视它 —— 连带
            # 把真正该看的 server 降级也一起无视掉。
            expr = ''
              tailscale_peer_direct{kind="server"} == 0
              and on(instance, peer) tailscale_peer_active{kind="server"} == 1
              and on(instance, peer) tailscale_peer_online{kind="server"} == 1
            '';
            # 15 分钟。NAT 打洞本来就需要时间,重连后短暂走中继是正常的,
            # 不该为此报警。
            "for" = "15m";
            labels.severity = "warning";
            annotations = {
              summary = "{{ $labels.instance }} → {{ $labels.peer }} 降级成 DERP 中继了";
              description = ''
                这对机器本来直连,现在流量在走中继。常见原因是一侧的 IPv6 没了,
                或者 NAT 类型变了打不了洞。`tailscale ping {{ $labels.peer }}`
                看当前实际路径。
              '';
            };
          }
          {
            alert = "TailnetLinkPacketLoss";
            # 10% 丢包。ICMP 本来就可能被沿途限速,阈值给高一点。
            #
            # **对端在线是必要条件。** 关掉一台机器,其余 N-1 台到它的链路
            # 全部变成 100% 丢包,于是一台机器下线就刷出 N-1 条告警 —— 而那
            # 件事 HostUnreachable 已经报了一条,说得更准。实测 r2s 离线时
            # 这条规则一口气 firing 了 7 次,把同时存在的**真问题**
            # (多台到 r5sjp 12-20% 丢包)埋在里面看不见。
            expr = ''
              ping_loss_ratio > 0.25
              and on(instance, peer) tailscale_peer_online{kind="server"} == 1
            '';
            "for" = "15m";
            labels.severity = "warning";
            annotations.summary = "{{ $labels.instance }} → {{ $labels.peer }} 丢包 {{ $value | humanizePercentage }}";
          }
          {
            # 不设固定阈值 —— 这个 fleet 跨中日两地,r6s 4ms 和 r5sjp 177ms
            # 都是正常的,一个数字盖不住。改成和自己过去一天的基线比:
            # 涨到 2 倍并且绝对值超过 50ms 才算异常。
            alert = "TailnetLatencyDegraded";
            # 同样要求对端在线,理由见上面 TailnetLinkPacketLoss。
            expr = ''
              ping_rtt_mean_seconds
                > 2 * (avg_over_time(ping_rtt_mean_seconds[1d]) > 0)
              and ping_rtt_mean_seconds > 0.05
              and on(instance, peer) tailscale_peer_online{kind="server"} == 1
            '';
            "for" = "30m";
            labels.severity = "warning";
            annotations = {
              summary = "{{ $labels.instance }} → {{ $labels.peer }} 延迟涨到基线 2 倍({{ $value | humanizeDuration }})";
              description = "先看 TailscalePathDegraded 有没有同时触发 —— 多数情况下延迟翻倍就是因为降级到中继了。";
            };
          }
        ];
      }

      {
        name = "monitoring-self";
        rules =
          [
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
          ]
          ++ lib.optionals (monitorCount > 1) [
            {
              # **HA 退化成单点。** 这条是"两份"这件事本身的唯一保险 —— 少了它,
              # 另一份悄悄挂掉是完全无声的:面板照常、告警照常,因为活着的这份
              # 什么都能干。你会一直以为有冗余,直到剩下这份也挂掉的那天。
              #
              # 给 critical 而不是 warning:它描述的不是"现在有东西坏了",而是
              # "下一次故障将没有人报告"。2026-08-10 那次之后,这正是最该被当回事
              # 的一类状态。
              alert = "PrometheusPeerDown";
              expr = ''up{job="prometheus-peer"} == 0'';
              # 10 分钟,和 HostUnreachable 对齐 —— 对端重启一次不该报。
              "for" = "10m";
              labels.severity = "critical";
              annotations = {
                summary = "另一份 Prometheus({{ $labels.instance }})抓不到了";
                description = ''
                  监控退回单点:现在只剩这一份在采数,它再挂就彻底瞎了。
                  注意这条**没有**被 HostUnreachable 的 inhibit 规则压掉 ——
                  那条只压 warning/info,而这条是 critical,故意的。
                '';
              };
            }
            {
              # gossip 断了但两份都活着。后果和上面那条正相反:不是没人报,
              # 是同一件事被报两次 —— 两个 Alertmanager 各自以为只有自己在,
              # 于是各发各的。
              #
              # 只给 warning:告警还在发,只是吵。比反过来强得多。
              alert = "AlertmanagerClusterDegraded";
              expr = ''alertmanager_cluster_members < ${toString monitorCount}'';
              # 15 分钟。memberlist 收敛本来就需要几十秒,rebuild 重启一次
              # 也会短暂掉成员,不该为此报警。
              "for" = "15m";
              labels.severity = "warning";
              annotations = {
                summary = "Alertmanager 集群只剩 {{ $value }}/${toString monitorCount} 个成员";
                description = ''
                  两份 Alertmanager 之间的 gossip(9094,TCP+UDP)断了。
                  告警不会漏发,但会重复 —— 每条都会在群里出现两次。
                  先确认 tailscale 通不通,再看 9094 的 UDP 有没有被挡。
                '';
              };
            }
          ];
      }
    ];
  }
