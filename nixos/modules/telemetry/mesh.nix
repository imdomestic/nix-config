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

  peerNamesJson = builtins.toJSON (map (h: h.name) peers);

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
        | jq -r --argjson peers ${lib.escapeShellArg peerNamesJson} \
               -f ${./tailscale-path.jq} \
        > "$tmp"

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
  };
}
