# 抓取端:Prometheus + Grafana。整个 fleet 只有一份,跑在 tank 上。
#
# 为什么是 tank 而不是 h610:h610 已经背着 headscale、max、napcat、cliproxy、
# nginx、docker,而 Prometheus 的 TSDB 是要吃盘的,tank 才是那台有存储的机器。
#
# 抓取目标不手维护 —— 从 host registry 经 lib/mkInventory.nix 生成,和各台机器
# 上 node_exporter 的开关读同一个字段(my.host.tsIp)。参见 docs/maxops.md §8。
{
  config,
  lib,
  pkgs,
  inputs,
  ...
}: let
  cfg = config.my.monitoring;

  # Grafana 用它加密存在自己 DB 里的东西(主要是 datasource 口令)。26.05 起
  # nixpkgs 不再给默认值,必须显式提供。
  #
  # 三条路:硬编码上游那个人尽皆知的旧默认值、走 sops、或者本机生成一次。
  # 选第三条:
  #   - 硬编码等于把密钥写进 world-readable 的 nix store,而且是个公开常量。
  #   - sops 要往 secrets/hosts/tank.yaml 加键,不加就 `just check-sops` 红。
  #   - 本机生成不进 store、不进 git、不需要协调,而且这把钥匙没有跨机共享的
  #     需求 —— 它只解密 tank 自己那个 grafana.db。
  #
  # 代价:换机器/重装要么带上这个文件,要么接受 DB 里的密文作废(当前只有一个
  # 无口令的 Prometheus datasource,作废了也没有任何损失)。
  grafanaSecretKeyFile = "${config.services.grafana.dataDir}/secret_key";

  inventory =
    (import ../../../lib/mkInventory.nix {inherit inputs;})
    {hosts = import ../../hosts {inherit inputs;};};

  # 自己这台的地址。Prometheus 和 Grafana 都只绑它。
  selfIp = config.my.host.tsIp;
in {
  options.my.monitoring = {
    enable = lib.mkEnableOption "fleet 监控中心(Prometheus + Grafana),整个 fleet 只该有一台开";

    port = lib.mkOption {
      type = lib.types.port;
      default = 9009;
      description = ''
        Prometheus 端口。**不是默认的 9090** —— `nixos/profiles/server.nix`
        给所有 server 开了 cockpit 在 9090,撞了。cockpit 已经全 fleet 部署,
        挪 Prometheus 的代价小得多。
      '';
    };

    grafanaPort = lib.mkOption {
      type = lib.types.port;
      default = 3000;
      description = "Grafana 端口。3000 在这个 fleet 上是空的(h610 那个 3000 是注释掉的 headplane)。";
    };

    scrapeInterval = lib.mkOption {
      type = lib.types.str;
      default = "30s";
      description = ''
        30s 而不是默认的 15s。抓取目标里有 rpi4/r2s/r5s/r6s 这些 ARM 小机器,
        而且 r5sjp 在日本、shanghai 在机房,每次抓取都是一次跨站点往返。
        15s 对这套拓扑没有额外信息量,只是把采集本身变成负载。
      '';
    };

    retention = lib.mkOption {
      type = lib.types.str;
      default = "90d";
      description = ''
        90 天。够看清季节性(比如梅雨季 ARM 机器的温度、寒暑假的流量变化),
        又不至于让 TSDB 长到需要单独规划存储。8 台机器按 30s 间隔算,
        大致是几个 GB 的量级,tank 上不算事。
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = selfIp != null;
        message = ''
          my.monitoring 开在了 ${config.my.host.name} 上,但这台没有设
          my.host.tsIp。Prometheus 和 Grafana 都必须绑定确定的 tailscale
          地址 —— 这个 fleet 上全部 8 台纳管机器都是
          networking.firewall.enable = false,绑定地址是唯一真正起作用的边界,
          回落到 0.0.0.0 等于直接挂到每一张网卡上。
        '';
      }
      {
        assertion = inventory != [];
        message = ''
          没有任何一台机器设置了 my.host.tsIp,Prometheus 会起来但一个目标
          都没有。检查 nixos/hosts/*/default.nix。
        '';
      }
    ];

    services.prometheus = {
      enable = true;

      # 只绑 tailscale。同 node_exporter,理由见 modules/telemetry。
      listenAddress = selfIp;
      port = cfg.port;
      retentionTime = cfg.retention;

      globalConfig = {
        scrape_interval = cfg.scrapeInterval;
        # 抓取超时必须小于间隔,否则慢目标会让抓取排队堆积。r5sjp 跨海,
        # 给够 10s。
        scrape_timeout = "10s";
      };

      scrapeConfigs = [
        {
          job_name = "node";
          # 一台机器一个 static_config,这样 labels 能逐台给。
          static_configs =
            map (h: {
              targets = ["${h.tsIp}:9100"];
              labels = {
                # instance 默认会是 "100.64.0.5:9100" 这种,查询和看板里
                # 全是 IP,认不出来。覆盖成 registry 里的主机名。
                instance = h.name;
                # 让告警规则和看板能按角色/架构切,不用把主机名写死进查询。
                arch = h.system;
                roles = lib.concatStringsSep "," h.roles;
              };
            })
            inventory;
        }
        {
          # 抓自己。监控系统本身不被监控是个典型盲区 —— 抓取失败、
          # TSDB 写不动、规则求值超时,都只有这个 job 能看见。
          job_name = "prometheus";
          static_configs = [
            {
              targets = ["${selfIp}:${toString cfg.port}"];
              labels.instance = config.my.host.name;
            }
          ];
        }
      ];
    };

    services.grafana = {
      enable = true;

      settings = {
        server = {
          http_addr = selfIp;
          http_port = cfg.grafanaPort;
          domain = selfIp;
          root_url = "http://${selfIp}:${toString cfg.grafanaPort}/";
        };

        analytics = {
          reporting_enabled = false;
          check_for_updates = false;
        };

        # 文件内容由下面的 preStart 首次启动时生成,见文件顶部的说明。
        # `$__file{}` 是 Grafana 自己的 file provider 语法,不是 Nix 的插值 ——
        # 这里用单引号转义,别把它当成 antiquotation 改掉。
        security.secret_key = "$__file{${grafanaSecretKeyFile}}";

        # tailnet 就是这里的认证边界 —— headscale 的 ACL 已经把能连上来的人
        # 限定成 group:imdomestic 那四个,和 r6s 上 metacubexd 面板
        # (http://100.64.0.5:9090/ui)是同一个思路。匿名只给 Viewer,
        # 改看板还是要登录。
        #
        # 注意 admin 口令现在还是 grafana 默认的 admin/admin。要收紧就把
        # 口令放 sops:
        #
        #   sops.secrets."grafana/admin_password".owner = "grafana";
        #   services.grafana.settings.security.admin_password =
        #     "$__file{${config.sops.secrets."grafana/admin_password".path}}";
        #
        # 没直接写进来是因为 secrets/hosts/tank.yaml 里还没有这个键,
        # `just check-sops` 会红。加了键再打开上面两行。
        "auth.anonymous" = {
          enabled = true;
          org_name = "Main Org.";
          org_role = "Viewer";
        };
      };

      provision.datasources.settings = {
        apiVersion = 1;
        datasources = [
          {
            name = "Prometheus";
            type = "prometheus";
            access = "proxy";
            # **必须是 selfIp,不能"顺手优化"成 127.0.0.1。** Prometheus 只
            # 接受一个 listen 地址,而上面把它绑到了 tailscale 地址上,回环
            # 根本没有监听。同机通信绕一下 tailscale0 的开销可以忽略。
            url = "http://${selfIp}:${toString cfg.port}";
            isDefault = true;
          }
        ];
      };
    };

    # 这个 fleet 现在 8 台全是 firewall.enable = false,下面两条是空转的。
    # 留着是为了模块自身正确:哪天某台把防火墙打开,监控不会莫名其妙失联。
    # 注意是 interfaces.tailscale0 而不是全局 allowedTCPPorts —— 只在
    # tailscale 接口上放行,不碰 WAN。
    networking.firewall.interfaces.tailscale0.allowedTCPPorts = [
      cfg.port
      cfg.grafanaPort
    ];

    systemd.services.prometheus = {
      after = ["network-online.target" "tailscaled.service"];
      wants = ["network-online.target" "tailscaled.service"];
      serviceConfig.RestartSec = "10s";
    };

    systemd.services.grafana = {
      after = ["network-online.target" "tailscaled.service"];
      wants = ["network-online.target" "tailscaled.service"];
      serviceConfig.RestartSec = "10s";

      # mkAfter:上游的 preStart 会往 dataDir 里 ln -fs conf/tools,别覆盖掉。
      # 这段以 User=grafana 跑,写自己的 dataDir 不需要提权。
      # 幂等 —— 只在文件不存在或为空时生成,所以重启和 rebuild 都不会换钥匙
      # (换了的话 DB 里已有的密文就解不开了)。
      preStart = lib.mkAfter ''
        if [ ! -s ${grafanaSecretKeyFile} ]; then
          ( umask 077
            ${pkgs.coreutils}/bin/head -c 32 /dev/urandom \
              | ${pkgs.coreutils}/bin/base64 -w0 > ${grafanaSecretKeyFile} )
        fi
      '';
    };
  };
}
