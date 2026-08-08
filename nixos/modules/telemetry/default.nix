# 采集端:每台被纳管的机器上跑一个 node_exporter。
#
# 纳管与否由 `my.host.tsIp` 单独决定 —— 设了就采,没设就不采。tank 上的
# Prometheus 抓取目标读的是同一个字段(见 nixos/modules/monitoring),所以
# 不可能出现"开了 exporter 没人抓"或者"配了抓取目标但对面没开"。加一台机器
# 只需要在 registry 里填一行 tsIp。
{
  config,
  lib,
  ...
}: let
  cfg = config.my.telemetry;
in {
  imports = [./mesh.nix ./nix-builds.nix];

  options.my.telemetry = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = config.my.host.tsIp != null;
      defaultText = lib.literalExpression "config.my.host.tsIp != null";
      description = ''
        默认跟着 `my.host.tsIp` 走。要单独关掉某台机器就显式写 false,
        但注意 Prometheus 那边的抓取目标也是从 tsIp 生成的 —— 只关这边
        会让那台机器在监控里变成"一直抓不到",而不是"不监控"。想彻底移出
        监控范围,把 tsIp 置空。
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 9100;
      description = "node_exporter 端口。9100 是约定俗成,全 fleet 统一。";
    };

    collectors = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = ["systemd" "netdev" "netstat" "processes"];
      description = ''
        默认之外额外启用的 collector。

        `systemd` 是这里面最重要的一个:它导出 `node_systemd_unit_state`,
        也就是"服务运行状态"。有它就不需要另做一套服务健康检查 —— 这也是
        为什么 maxops 的只读操作里 `units.failed` 能直接从 Prometheus 答,
        不用逐台去问 agent。

        `processes` 给进程数和状态分布,判断 fork 炸弹/僵尸堆积用得上,
        开销很小。
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # 这条断言是 fail-closed 的关键。没有它,tsIp 忘了填时 listenAddress
    # 会拿到 null,而 nixpkgs 那边的默认是 "0.0.0.0" —— 在下面这几台
    # firewall.enable = false 的机器上,那等于把 exporter 直接挂出去。
    # 宁可求值失败也不要静默降级成公开监听。
    assertions = [
      {
        assertion = config.my.host.tsIp != null;
        message = ''
          my.telemetry.enable 为 true,但 ${config.my.host.name} 没有设
          my.host.tsIp。node_exporter 必须绑定一个确定的 tailscale 地址,
          不能回落到 0.0.0.0。在 nixos/hosts/${config.my.host.name}/default.nix
          里补上 tsIp,或者把 my.telemetry.enable 显式设成 false。
        '';
      }
    ];

    services.prometheus.exporters.node = {
      enable = true;

      # **只绑 tailscale 地址。** r2s/r5s/r5sjp/shanghai/r6s/rpi4 这几台是
      # firewall.enable = false,`openFirewall` 在它们身上是空操作,绑定
      # 地址是那里唯一真正起作用的边界。
      #
      # 别小看这个 exporter 的信息量:开了 systemd collector 之后它会导出
      # 全部 unit 名字和状态。对跑着 xray/mihomo/wireguard 的这几台机器来说,
      # 那是一份完整的服务清单,不该落到 tailnet 之外。
      listenAddress = config.my.host.tsIp;
      port = cfg.port;

      # 显式 false,不是省略。上面那几台没有防火墙可开,而有防火墙的那几台
      # 也不需要 —— 走 tailscale0 进来的流量不经 allowedTCPPorts 判定。
      # 写 true 会给人"已经拦过一道"的错觉,那是 r6s 和 rpi4 之前的状态:
      # 两台都 firewall.enable = false,openFirewall = true 一直是摆设。
      openFirewall = false;

      enabledCollectors = cfg.collectors;
    };

    systemd.services.prometheus-node-exporter = {
      # 绑的是 tailscale 地址,tailscaled 没起来的话这个地址还不存在,
      # bind 会直接失败。同 modules/cliproxy。
      after = ["network-online.target" "tailscaled.service"];
      wants = ["network-online.target" "tailscaled.service"];

      # tailscaled 起来 ≠ 地址已经配好,中间有个窗口。nixpkgs 那边给的是
      # Restart = mkDefault "always" 但没设 RestartSec,默认 100ms 会在这个
      # 窗口里空转几十次。10s 退避,拿一点点启动延迟换干净的日志。
      serviceConfig.RestartSec = "10s";
    };
  };
}
