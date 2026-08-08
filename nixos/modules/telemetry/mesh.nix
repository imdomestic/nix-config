# tailnet 网状延迟 + 路径类型。
#
# 分两层,缺一层都不好用:
#
#   ping_exporter    → 延迟数字(min/mean/max/stddev + 丢包)
#   textfile 采集器  → 这条链路是直连还是走 DERP 中继
#
# **只有数字是不够的。** "r5sjp 从 40ms 变成 200ms" 这句话本身没有行动指向;
# "r5sjp 从直连降级成了经 h610 的中继" 才有。而后者只有各节点自己的 tailscaled
# 知道 —— headscale 是控制平面,它不掌握两个节点之间走哪条路,所以社区那个
# tailscale-exporter(走 headscale API)给不了这个信息。
#
# 两层还互相成就:tailscale 只在链路 active 时才填 CurAddr,而 ping_exporter
# 每 5 秒打一轮恰好让所有 pair 一直保持 active,路径判断才有效。详见
# tailscale-path.jq 文件头。
{
  config,
  lib,
  pkgs,
  inputs,
  ...
}: let
  cfg = config.my.telemetry;

  inventory =
    (import ../../../lib/mkInventory.nix {inherit inputs;})
    {hosts = import ../../hosts {inherit inputs;};};

  # 除自己以外的纳管机器。
  peers = lib.filter (h: h.name != config.my.host.name) inventory;

  # 全部纳管机器的名字(含自己,无害)。jq 靠它把 peer 分成 server / device。
  serverNamesJson = builtins.toJSON (map (h: h.name) inventory);

  pathScript = pkgs.writeShellApplication {
    name = "tailscale-path-metrics";
    runtimeInputs = [pkgs.tailscale pkgs.jq pkgs.coreutils];
    text = ''
      dir=${lib.escapeShellArg cfg.textfileDir}
      out="$dir/tailscale_path.prom"

      # 写临时文件再 mv。node_exporter 会在任意时刻读这个目录,读到写了一半的
      # 文件会整个 .prom 报错丢弃 —— mv 在同一文件系统上是原子的。
      tmp="$(mktemp "$dir/.tailscale_path.XXXXXX")"
      trap 'rm -f "$tmp"' EXIT

      tailscale status --json \
        | jq -r --argjson servers ${lib.escapeShellArg serverNamesJson} \
               -f ${./tailscale-path.jq} \
        > "$tmp"

      chmod 0644 "$tmp"
      mv "$tmp" "$out"
    '';
  };

  # 终端设备(手机、别人的 MacBook)的 RTT。
  #
  # 为什么不用 ping_exporter:那需要一份静态目标列表,而这些设备来来去去 ——
  # 二十来台里通常只有三五台在线,还时不时多一台新手机。把列表写进 nix 意味着
  # 手工维护一份必然过期的清单,而且会给二十个常年离线的目标持续打 ICMP。
  #
  # 改成从 `tailscale status` 里挑出**当前在线**的设备再 `tailscale ping`:
  #   - 自动发现,新设备加进 tailnet 就自动被测,不用改配置
  #   - 自动收敛,离线的根本不探,工作量随在线数走而不是随注册数走
  #   - 测的是真实 tailnet 路径(经不经 DERP 都算进去),而不是 ICMP
  #
  # 探不到就什么都不输出 —— 在 Prometheus 里是序列缺失,不是一个假的 0 或者
  # 一个假的超大值。看板那边靠时间窗聚合来填,见 dashboards/devices.json。
  deviceRttScript = pkgs.writeShellApplication {
    name = "tailscale-device-rtt";
    runtimeInputs = [pkgs.tailscale pkgs.jq pkgs.coreutils pkgs.gnused];
    text = ''
      dir=${lib.escapeShellArg cfg.textfileDir}
      out="$dir/tailscale_device_rtt.prom"
      tmp="$(mktemp "$dir/.tailscale_device_rtt.XXXXXX")"
      trap 'rm -f "$tmp"' EXIT

      {
        echo "# HELP tailscale_device_rtt_seconds Round-trip time to an online terminal device, measured with tailscale ping."
        echo "# TYPE tailscale_device_rtt_seconds gauge"
      } > "$tmp"

      # 只挑 kind=device 且 Online 的。上限 ${toString cfg.deviceProbeLimit} 台
      # 是防跑飞的:每台最坏 ${cfg.deviceProbeTimeout} 超时,乘起来必须明显小于
      # timer 间隔,否则会开始堆叠。
      tailscale status --json \
        | jq -r --argjson servers ${lib.escapeShellArg serverNamesJson} '
            .User as $u
            | .Peer // {} | to_entries[] | .value
            | select((.DNSName // "") != "")
            | (.DNSName | split(".")[0]) as $n
            | select(($servers | index($n)) == null)
            | select((.Online // false) == true)
            | [ $n,
                (.TailscaleIPs // ["-"])[0],
                (.OS // "unknown"),
                ($u[((.UserID // 0) | tostring)].LoginName // "unknown") ]
            | @tsv
          ' \
        | head -n ${toString cfg.deviceProbeLimit} \
        | while IFS="$(printf '\t')" read -r name ip os user; do
            [ "$ip" = "-" ] && continue

            line=""
            if ! line="$(tailscale ping -c 1 --timeout ${cfg.deviceProbeTimeout} \
                           --until-direct=false "$ip" 2>/dev/null | head -1)"; then
              line=""
            fi

            # 超时那行是 `ping "100.64.0.x" timed out`,匹配不到 `in <n>ms`,
            # 于是这里为空,直接跳过 —— 不输出任何样本。
            ms="$(printf '%s' "$line" | sed -n 's/.* in \([0-9][0-9]*\)ms$/\1/p')"
            [ -z "$ms" ] && continue

            # 走中继时输出形如 `... via DERP(h610) in 45ms`;直连是
            # `... via [2409:...]:41641 in 4ms`。
            if printf '%s' "$line" | grep -q 'DERP('; then
              via=derp
              region="$(printf '%s' "$line" | sed -n 's/.*DERP(\([^)]*\)).*/\1/p')"
            else
              via=direct
              region=""
            fi

            printf 'tailscale_device_rtt_seconds{peer="%s",kind="device",os="%s",user="%s",via="%s",region="%s"} %s\n' \
              "$name" "$os" "$user" "$via" "$region" \
              "$(awk -v m="$ms" 'BEGIN { printf "%.4f", m / 1000 }')"
          done >> "$tmp"

      chmod 0644 "$tmp"
      mv "$tmp" "$out"
    '';
  };
in {
  options.my.telemetry = {
    mesh = lib.mkOption {
      type = lib.types.bool;
      default = cfg.enable && peers != [];
      defaultText = lib.literalExpression "my.telemetry.enable && 有其它纳管机器";
      description = ''
        是否参与网状延迟探测。默认跟着 telemetry 走。

        全网状(8 台各 ping 其余 7 台,56 条有向边)而不是从 tank 单点辐射:
        ICMP 那点流量可以忽略,但换来一个关键能力 —— 区分"r5sjp 从哪儿都慢"
        (它自己的问题)和"r5sjp 只从 shanghai 慢"(那条路径的问题)。单点
        测量永远分不开这两种。
      '';
    };

    pingPort = lib.mkOption {
      type = lib.types.port;
      default = 9427;
      description = "ping_exporter 端口(上游默认),全 fleet 无冲突。";
    };

    deviceProbeLimit = lib.mkOption {
      type = lib.types.int;
      default = 12;
      description = ''
        单轮最多探测多少台在线终端设备。防跑飞用 —— limit × timeout 必须
        明显小于 timer 间隔(60s),否则任务会开始堆叠。12 × 2s = 24s,
        而实际同时在线的通常只有三五台。
      '';
    };

    deviceProbeTimeout = lib.mkOption {
      type = lib.types.str;
      default = "2s";
      description = ''
        单台设备的 ping 超时。给得短:手机在锁屏/弱网下本来就可能不应答,
        为一台没反应的设备等 5 秒没意义 —— 探不到就不输出样本,看板靠
        时间窗聚合来填空。
      '';
    };

    textfileDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/prometheus-node-exporter-textfile";
      description = ''
        node_exporter 的 textfile 采集目录。路径状态从这里进 node_exporter,
        所以不需要额外的服务、端口和抓取 job。
      '';
    };
  };

  config = lib.mkIf cfg.mesh {
    services.prometheus.exporters.ping = {
      enable = true;
      # 同 node_exporter:只绑 tailscale 地址。这个 fleet 8 台全是
      # firewall.enable = false,绑定地址是唯一真正起作用的边界。
      listenAddress = config.my.host.tsIp;
      port = cfg.pingPort;

      settings = {
        # 用 IP 不用 MagicDNS 名字:tank 上没有 services.resolved,不能假设
        # 每台都能解析 *.inner.imdomestic.com。IP 字面量零依赖,而可读的
        # peer 名字在 Prometheus 侧用 relabel 补回来(见 modules/monitoring)。
        targets = map (h: h.tsIp) peers;

        ping = {
          # 5 秒一轮、留 24 个历史点 = 2 分钟窗口,而抓取间隔是 30 秒。
          # 也就是每次抓取拿到的是过去两分钟的统计,不是一次采样 ——
          # 这正是用 ping_exporter 而不是 blackbox 的原因。
          interval = "5s";
          timeout = "4s";
          history-size = 24;
        };
      };
    };

    systemd.services.prometheus-ping-exporter = {
      after = ["network-online.target" "tailscaled.service"];
      wants = ["network-online.target" "tailscaled.service"];
      serviceConfig.RestartSec = "10s";
    };

    # --- 路径类型:textfile 采集器 ---

    systemd.tmpfiles.rules = [
      "d ${cfg.textfileDir} 0755 root root -"
    ];

    services.prometheus.exporters.node.extraFlags = [
      "--collector.textfile.directory=${cfg.textfileDir}"
    ];

    systemd.services.tailscale-path-metrics = {
      description = "把 tailscale 的链路状态写成 node_exporter textfile 指标";
      after = ["tailscaled.service"];
      wants = ["tailscaled.service"];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = lib.getExe pathScript;
        # 需要 root:tailscaled 的控制 socket 默认只有 root 能读。
        # 只是个只读的 status 查询,所以其余能关的都关掉。
        User = "root";
        ReadWritePaths = [cfg.textfileDir];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        RestrictAddressFamilies = ["AF_UNIX" "AF_INET" "AF_INET6"];
        RestrictNamespaces = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
      };
    };

    systemd.timers.tailscale-path-metrics = {
      wantedBy = ["timers.target"];
      timerConfig = {
        # 抓取间隔是 30 秒,这里也 30 秒。再密没有意义 —— Prometheus 看不到
        # 两次抓取之间的变化。
        OnBootSec = "1m";
        OnUnitActiveSec = "30s";
        AccuracySec = "5s";
      };
    };

    # 设备 RTT 单独一个 unit,不和上面那个合并:上面是纯解析本地状态,毫秒级
    # 就跑完;这个要对每台在线设备发真实网络请求,最坏几十秒。混在一起会让
    # 路径指标被慢探测拖着一起延迟。
    systemd.services.tailscale-device-rtt = {
      description = "探测在线终端设备的 tailnet RTT,写成 node_exporter textfile 指标";
      after = ["tailscaled.service"];
      wants = ["tailscaled.service"];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = lib.getExe deviceRttScript;
        # 硬超时兜底:脚本自己有 limit × timeout 的上界,但万一 tailscale ping
        # 卡住不返回,也不能让这个 unit 永远挂着堵住下一轮。
        TimeoutStartSec = "50s";
        User = "root";
        ReadWritePaths = [cfg.textfileDir];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        RestrictAddressFamilies = ["AF_UNIX" "AF_INET" "AF_INET6"];
        RestrictNamespaces = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
      };
    };

    systemd.timers.tailscale-device-rtt = {
      wantedBy = ["timers.target"];
      timerConfig = {
        # 60 秒而不是 30 秒。终端设备的延迟不需要高分辨率 —— 手机在蜂窝网上
        # 本来就抖,而且这一轮要发真实网络请求,频率低一点对设备电量也友好。
        OnBootSec = "2m";
        OnUnitActiveSec = "60s";
        AccuracySec = "10s";
        # 七台服务器同时探同一批设备的话,每台设备每分钟会挨七次 ping。
        # 打散开,免得所有服务器在同一秒集中打过去。
        RandomizedDelaySec = "20s";
      };
    };
  };
}
