# Grafana 的统一入口:一个地址,后面挂着两份 Grafana,前面那份连不上就自动
# 换后面那份。
#
# 为什么需要它:HA 之后 tank 和 h610 各跑一份 Grafana(见 ./default.nix),
# 于是看板有了两个地址。真到停电那天,人是记不住"这次该开哪个"的 —— 而记不住
# 的后果就是没人去看。
#
# **为什么不做成"一份 Grafana 配两个数据源":** 那样 Grafana 自己就是单点,
# 正好回到这次要解决的问题上。Grafana 开源版也没有真正的 HA —— 官方那套是多
# 实例共享一个外部 Postgres/MySQL,而那个库又是个新的单点。所以"一个入口"只能
# 在 Grafana 外面解决。
#
# **为什么入口放在第三台(shanghai)而不是那两份里的任意一台:** 放在 tank 或
# h610 上,那台一挂入口就跟着没了,等于白做。shanghai 在机房、是独立的故障域,
# 而且本来就有 nginx。
#
# **为什么不是 keepalived/VRRP 那种浮动 IP:** 那要求两台在同一个二层网段。
# tank 和 h610 本来就故意放在不同地方,直接出局。
#
# 入口挂了怎么办:直接敲那两台的地址,`http://<tsIp>:3000`,两份都是完整的。
# 也就是说这一层只是便利,不在故障路径上 —— 告警更是完全不经过它,
# Alertmanager 集群自己就把通知发出去了。
{
  config,
  lib,
  inputs,
  ...
}: let
  cfg = config.my.monitoring;

  inventory =
    (import ../../../lib/mkInventory.nix {inherit inputs;})
    {hosts = import ../../hosts {inherit inputs;};};

  # 后端就是那几份监控,同样从 registry 派生 —— 和 ./default.nix 读的是同一个
  # roles 字段,所以加一份监控不需要回来改这里。
  monitors = lib.filter (h: lib.elem "monitor" h.roles) inventory;

  selfIp = config.my.host.tsIp;
in {
  options.my.monitoring.gateway = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = lib.elem "monitor-gateway" config.my.host.roles;
      defaultText = lib.literalExpression ''lib.elem "monitor-gateway" config.my.host.roles'';
      description = ''
        在这台上跑 Grafana 的故障转移入口。只是一个 nginx,不跑 Prometheus,
        也不存任何东西。

        默认从 registry 的 roles 派生("monitor-gateway"),和 my.monitoring.enable
        是同一个套路。
      '';
    };

    primary = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "tank";
      description = ''
        平时优先转发到哪一份 Grafana。其余的都是 backup,只在它连不上时才用。

        **不写的话取 inventory 里的第一台,而那是按主机名字母序排的** ——
        也就是说重命名一台机器会静默地把主后端换掉。真在意用哪台就显式写出来。

        两份 Grafana 的看板和数据源完全一样(都由 nix 下发),所以这个选择
        影响的只是"平时压在谁身上",不影响能看到什么。
      '';
    };
  };

  config = lib.mkIf cfg.gateway.enable {
    assertions = [
      {
        assertion = selfIp != null;
        message = ''
          my.monitoring.gateway 开在了 ${config.my.host.name} 上,但这台没设
          my.host.tsIp。入口只绑 tailscale 地址 —— 理由同 Prometheus,
          见 nixos/modules/telemetry/default.nix 里那条断言。
        '';
      }
      {
        assertion = monitors != [];
        message = ''
          my.monitoring.gateway 开着,但没有任何一台的 roles 里有 "monitor",
          入口后面一个后端都没有。检查 nixos/hosts/*/default.nix。
        '';
      }
      {
        assertion =
          cfg.gateway.primary
          == null
          || lib.any (m: m.name == cfg.gateway.primary) monitors;
        message = ''
          my.monitoring.gateway.primary 是 "${toString cfg.gateway.primary}",
          但这台不在跑监控的名单里(roles 含 "monitor" 的只有:
          ${lib.concatMapStringsSep ", " (m: m.name) monitors})。

          写错名字如果不拦,结果是它被静默忽略、主后端悄悄变回字母序第一台。
        '';
      }
      {
        # 端口会撞:两边都是 grafanaPort,而且都绑在同一个 tsIp 上。
        assertion = !cfg.enable;
        message = ''
          ${config.my.host.name} 同时开了 my.monitoring.enable 和
          my.monitoring.gateway.enable。入口和 Grafana 都要监听
          ${toString cfg.grafanaPort},绑的还是同一个地址,后起的那个会
          bind 失败。

          而且这么配本身就没意义:入口的全部价值在于它和两份 Grafana 处在
          不同的故障域,放在其中一份上等于没做。
        '';
      }
    ];

    services.nginx.enable = true;

    services.nginx.upstreams.grafana = {
      # 恰好一台是主(backup = false),其余全是 backup。**这不是负载均衡** ——
      # Grafana 的会话和"最近看过哪个看板"存在各自的 sqlite 里,轮询会让人
      # 一会儿登录着一会儿又没登录。要的是故障转移,不是分流。
      #
      # 主是谁:显式配了 primary 就用它,否则退回 monitors 的第一项。注意
      # inventory 是 mapAttrsToList 出来的,**顺序是主机名的字母序**,所以
      # "第一项"是个稳定但没有含义的选择 —— 在意就写 primary。
      servers = lib.listToAttrs (
        lib.imap0 (
          i: m:
            lib.nameValuePair "${m.tsIp}:${toString cfg.grafanaPort}" {
              backup =
                if cfg.gateway.primary != null
                then m.name != cfg.gateway.primary
                else i > 0;
            }
        )
        monitors
      );
    };

    services.nginx.virtualHosts."grafana-ha" = {
      # 只绑 tailscale,和这个 fleet 里其它面板一个路子(r6s 的 metacubexd 在
      # 100.64.0.5:9090,Grafana 本体在 <tsIp>:3000)。**故意不做
      # grafana.imdomestic.com + acme**:那要多一条 Cloudflare 记录和一张证书,
      # 而 tailnet 已经是这里的认证边界了,headscale 的 ACL 圈定了能连进来的人。
      listen = [
        {
          addr = selfIp;
          port = cfg.grafanaPort;
        }
      ];

      locations."/" = {
        proxyPass = "http://grafana";
        # Grafana 的实时刷新和 Explore 走 websocket,不开的话面板能看但
        # 一部分交互会静默失效。
        proxyWebsockets = true;
        extraConfig = ''
          # 这三行是整个故障转移的落点。没有它们 nginx 只在**建连**失败时
          # 才换后端,而 Grafana 进程还活着但卡死(比如 sqlite 锁住)的时候
          # 连是能连上的,请求会一直挂在那台上。
          proxy_next_upstream error timeout http_502 http_503 http_504;
          proxy_next_upstream_tries 2;

          # 默认 60s。一台断电的机器在 tailscale 上表现为静默丢包,60s 意味着
          # 你要对着转圈的浏览器等一分钟才切过去 —— 而这正是最需要看板的时候。
          proxy_connect_timeout 3s;
        '';
      };
    };

    networking.firewall.interfaces.tailscale0.allowedTCPPorts = [cfg.grafanaPort];
  };
}
