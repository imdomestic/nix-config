# 抓取端:Prometheus + Alertmanager + Grafana。**跑两份**,tank 和 h610 各一份。
#
# 为什么是两份:2026-08-10 tank 所在的地方停电,整套监控跟着一起没了 —— 一条
# 告警都没发出来,因为负责发告警的就是挂掉的那台。Prometheus 的 HA 就是上游
# 给的那个办法:**跑两个一模一样的实例抓同一批 target,各写各的本地 TSDB,
# 谁也不知道对方存在。** 不需要共享存储、不需要选主、不需要编排器 —— 这也是
# 为什么它不该被换成"上 k8s 让 pod 漂过去":pod 漂过去只会得到一个空 TSDB,
# 而想让盘跟着漂就得在跨城链路上同步复制一个持续写入的时序库。
#
# 两份之间唯一需要协调的是 Alertmanager:它们靠 gossip(9094)组成集群,同一条
# 告警只往外发一次。这是整套里唯一一处真正的分布式协调,而且降级得很温和 ——
# gossip 断了的后果是同一条告警发两遍,不是不发。
#
# 为什么是 tank + h610:这两台在不同的供电域(实测 tank 停电一整天期间 h610
# 全程在线),而故障域不同才是"两份"的全部意义 —— 同一个屋子里放两份等于
# 还是一份。
#
# 抓取目标不手维护 —— 从 host registry 经 lib/mkInventory.nix 生成,和各台机器
# 上 node_exporter 的开关读同一个字段(my.host.tsIp)。参见 docs/maxops.md §8。
# **谁跑监控同样从 registry 派生:roles 里有 "monitor" 就是一份。**
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

  # 谁在跑监控 —— 和抓取目标一样从 registry 派生,不手维护第二份名单。
  # 加/减一份监控 = 改 nixos/hosts/<name>/default.nix 里 roles 那一行,
  # 本机的开关、对端的 Alertmanager gossip 名单、Grafana 的第二个数据源、
  # 以及"另一份挂了"那条告警的预期成员数,四处同时跟着变。
  monitors = lib.filter (h: lib.elem "monitor" h.roles) inventory;

  # 除自己之外的那几份。单实例时是空表,下面所有跟 HA 相关的东西都会
  # 自动退化成原来的单机形态。
  peers = lib.filter (h: h.name != config.my.host.name) monitors;

  # Grafana 的统一入口(见 ./gateway.nix)。这里只用来把入口地址加进
  # Grafana 的 CSRF 白名单 —— 经代理进来的请求 Origin 是入口的地址,
  # 和各自的 root_url 对不上,不加白名单的话面板能打开但查询会 403。
  gateways = lib.filter (h: lib.elem "monitor-gateway" h.roles) inventory;

  # Alertmanager 的 gossip 端口。**写死 9094 是被上游逼的**:nixpkgs 那边
  # 把 peer 端口硬编码成了 `--cluster.peer ${peer}:9094`
  # (alertmanager.nix:35),所以监听端口也只能是 9094,否则两边对不上。
  clusterPort = 9094;
in {
  imports = [./gateway.nix];

  options.my.monitoring = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = lib.elem "monitor" config.my.host.roles;
      defaultText = lib.literalExpression ''lib.elem "monitor" config.my.host.roles'';
      description = ''
        在这台上跑一份监控(Prometheus + Alertmanager + Grafana)。

        **默认从 registry 的 roles 派生,正常情况下不要手写这个选项。**
        手写 true 而 roles 里没有 "monitor" 会得到一个半瘸的实例:它自己跑
        起来了,但别人的 peers 名单里没有它 —— Alertmanager 不会和它组集群
        (于是告警发重),也没有人监控它挂没挂。下面有断言拦这个情况。

        开成两份及以上就是 HA。两份之间不共享任何状态,各抓各的、各存各的,
        唯一的协调是 Alertmanager 的 gossip 去重。
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 9009;
      description = ''
        Prometheus 端口。**不是默认的 9090。**

        历史原因:profiles/server.nix 曾经给所有 server 开 cockpit 在 9090,
        当时 cockpit 已经全 fleet 部署,挪 Prometheus 代价更小。

        2026-08-12 cockpit 删了,9090 空了出来(r6s 上现在是 mihomo 的
        metacubexd 面板占着)。**但这里保持 9009 不动** —— 让路的理由没了,
        而端口已经写进两份监控配置、看板和 docs/maxops.md,再挪回去是净损失。
      '';
    };

    grafanaPort = lib.mkOption {
      type = lib.types.port;
      default = 3000;
      description = ''
        Grafana 端口。3000 在这个 fleet 上没有别的占用者。

        h610 上曾经有一份注释掉的 headplane 也写着 3000;2026-08-16 headplane
        真正启用时挪到了 3001,就是为了不跟这里撞(见 hosts/h610/system.nix)。
        Grafana 只绑 tsIp、headplane 也只绑 tsIp,同端口会是硬冲突。
      '';
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

    alertmanagerPort = lib.mkOption {
      type = lib.types.port;
      default = 9093;
      description = "Alertmanager 端口。9093 是上游默认,这个 fleet 上没冲突。";
    };

    webhookUrl = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "http://100.64.0.3:9722/alert";
      description = ''
        告警投递的去处。**null 时告警只进 Alertmanager 界面,不往外发。**

        这是 P2 的最后一公里,故意留成一个选项:告警规则和 Alertmanager 本身
        跟"发到哪"是两件事,前者现在就该上,后者取决于 max 那边暴露什么接口
        (见 docs/maxops.md,notify sink 最终归 maxops-hub 管)。

        null 不是"没配好",是一个有意义的中间状态 —— 规则先跑起来攒几天,
        看清楚哪几条会误报、哪几条太吵,调完了再接出口。**先接出口再调规则,
        第一周就会把群刷炸,然后所有人开始无视这个群。**
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
      {
        # 名单不对称是这套 HA 唯一一种会**静默**坏掉的方式:这台跑得好好的,
        # 面板也正常,但对端根本不知道它存在 —— 告警于是发两遍,而且这台挂了
        # 没有任何人报。所以宁可求值失败。
        assertion = lib.elem "monitor" config.my.host.roles;
        message = ''
          my.monitoring.enable 在 ${config.my.host.name} 上是 true,但
          nixos/hosts/${config.my.host.name}/default.nix 的 roles 里没有
          "monitor"。

          谁跑监控是从 registry 派生的:对端的 Alertmanager gossip 名单、
          "另一份挂了"那条告警的预期成员数,全都读 roles。只在这台上手写
          enable = true 会让它变成一份没人认识的孤儿实例 —— 告警重复发送,
          而且它自己挂了不会有任何告警。

          把 "monitor" 加进那台的 roles,别手写 enable。
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

      rules = [
        (import ./alerts.nix {
          inherit lib;
          monitorCount = builtins.length monitors;
        })
      ];

      # **推给所有 Alertmanager,不是只推自己那个。**
      #
      # 这是整套里唯一一处推送(抓取全是 pull),也是唯一一处 fan-out 有意义的
      # 地方:AM 的去重本来就是为"同一条告警从多个 Prometheus 收到"设计的,
      # 多推不会让群里多出一条。
      #
      # 只推本机的话会漏掉一种组合:本机 alertmanager.service 挂了(但本机
      # Prometheus 活着),同时对端 Prometheus 挂了(但对端 AM 活着)。这时
      # 一个 Prometheus 和一个 AM 都是好的,告警却一条都发不出去。交叉推送之后
      # 判据变成"任意一个 Prometheus + 任意一个 AM 活着"就能送达。
      #
      # 排序:monitors 已经是主机名字母序,两边生成的列表一致,没有隐含的优先级
      # —— Prometheus 对配置里的多个 alertmanager 是全发,不是挑一个。
      alertmanagers = [
        {
          static_configs = [
            {
              targets =
                map (m: "${m.tsIp}:${toString cfg.alertmanagerPort}") monitors;
            }
          ];
        }
      ];

      scrapeConfigs =
        [
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
            job_name = "ping";
            static_configs =
              map (h: {
                targets = ["${h.tsIp}:9427"];
                # instance = 发起探测的那台。被探测的那台在下面 relabel 成 peer,
                # 所以一条时序读起来是 "从 instance 打到 peer"。
                labels.instance = h.name;
              })
              inventory;

            # ping_exporter 的 target 标签是 IP(见 modules/telemetry/mesh.nix
            # 里为什么用 IP 而不是 MagicDNS 名字)。这里按 inventory 生成一组
            # 一一对应的改写规则,把它翻成主机名。
            #
            # 每条规则只在 target 精确等于某个 IP 时命中 —— Prometheus 的
            # relabel regex 是全锚定的。tsIp 里的点要转义,否则 `.` 会匹配任意
            # 字符(实际不会撞上,但错的正则迟早咬人)。
            metric_relabel_configs =
              map (h: {
                source_labels = ["target"];
                regex = lib.replaceStrings ["."] ["\\."] h.tsIp;
                target_label = "peer";
                replacement = h.name;
              })
              inventory;
          }
          {
            # 抓自己。监控系统本身不被监控是个典型盲区 —— 抓取失败、
            # TSDB 写不动、规则求值超时,都只有这个 job 能看见。
            #
            # **保持只抓自己。** 告警规则里 PrometheusSelfScrapeFailing 读的就是
            # `up{job="prometheus"}`,把对端塞进来会让那条"抓不到自己"对着别人
            # 触发,文案和结论都是错的。对端走下面的 prometheus-peer。
            job_name = "prometheus";
            static_configs = [
              {
                targets = ["${selfIp}:${toString cfg.port}"];
                labels.instance = config.my.host.name;
              }
            ];
          }
        ]
        ++ lib.optional (peers != []) {
          # **两份监控互相监控。** 少了这个 job,另一份悄悄挂掉不会有任何人
          # 知道 —— 你以为有两份,实际早就只剩一份,而这件事只会在剩下那份
          # 也挂掉的那天暴露出来。这正是 2026-08-10 那次的教训的第二层。
          #
          # 端口用本机的 cfg.port:my.monitoring.port 是每台各自的选项,理论上
          # 能配得不一样。全 fleet 统一走默认的 9009,真要改就一起改。
          job_name = "prometheus-peer";
          static_configs =
            map (p: {
              targets = ["${p.tsIp}:${toString cfg.port}"];
              labels.instance = p.name;
            })
            peers;
        }
        ++ lib.optional (peers != []) {
          # 抓所有 Alertmanager(含自己)。要的是 alertmanager_cluster_members ——
          # gossip 断了两边会把同一条告警各发一次,而那件事从告警内容上是看不
          # 出来的,只有这个指标能说明白。
          job_name = "alertmanager";
          static_configs =
            map (m: {
              targets = ["${m.tsIp}:${toString cfg.alertmanagerPort}"];
              labels.instance = m.name;
            })
            monitors;
        };
    };

    services.prometheus.alertmanager = {
      enable = true;
      listenAddress = selfIp;
      port = cfg.alertmanagerPort;

      # **HA 的全部协调就在这两行。** 两个 Alertmanager 用 memberlist gossip
      # 互相认识,然后对通知去重:两份 Prometheus 抓的是同一批 target,同一个
      # 故障必然在两边同时触发,没有这层的话群里每条告警都会出现两次。
      #
      # 去重是靠 gossip 同步"谁已经发过了"实现的,所以它降级得很温和 ——
      # 网络断了各发各的(重复),而不是互相等待(不发)。这个方向是对的:
      # 告警系统宁可吵也不能哑。
      clusterPeers = map (p: p.tsIp) peers;

      extraFlags =
        if peers == []
        then
          # 单实例。**必须显式关掉**,不能省略:上游默认监听 0.0.0.0:9094,
          # 而这个 fleet 全部 firewall.enable = false,省略等于凭空在每张网卡
          # 上开一个 gossip 端口。空值是 alertmanager 认的"禁用集群"写法。
          ["--cluster.listen-address="]
        else
          # 绑 tailscale 地址,同 Prometheus / node_exporter。绑到具体地址
          # 之后 advertise 地址也跟着确定,不用再单独指定。
          ["--cluster.listen-address ${selfIp}:${toString clusterPort}"];
      # Alertmanager 发出去的链接(比如"点这里静默")要用得上的地址。
      # 不设的话它会拿 hostname 拼,群里收到的链接点不开。
      webExternalUrl = "http://${selfIp}:${toString cfg.alertmanagerPort}";

      configuration = {
        route = {
          # 先按机器再按告警名分组:同一台机器同时炸出来的一堆问题(比如
          # 磁盘满导致一串服务失败)会合成一条消息,而不是刷屏。
          group_by = ["instance" "alertname"];

          # 首条等 1 分钟,让同一批相关告警聚齐再发。
          group_wait = "1m";
          # 同一组里出现新告警,至少隔 5 分钟再发一次。
          group_interval = "5m";
          # **同一条告警没恢复时,4 小时才重复提醒一次。**
          # 这个值是防止告警疲劳的关键。一台机器若长期离线,按默认的
          # 4 小时重复会一天在群里说 6 次,一周之后没人会再看这个群。
          # 长期不修的告警应该在 Alertmanager 界面里 silence 掉,而不是
          # 靠调低频率忍着。
          repeat_interval = "4h";

          receiver = "default";
        };

        # info 级的(比如 HostRebooted)不该和 critical 走同一条路,
        # 但现在只有一个 receiver,先靠 group_by 隔开。接了真出口之后
        # 这里要拆成 routes(critical 立刻发、warning 攒一攒、info 只留档)。
        receivers = [
          (
            {name = "default";}
            // lib.optionalAttrs (cfg.webhookUrl != null) {
              webhook_configs = [
                {
                  url = cfg.webhookUrl;
                  # 告警恢复也要发。只发"炸了"不发"好了"的系统,用两周之后
                  # 就没人相信它了 —— 你永远不知道手上这条是不是还成立。
                  send_resolved = true;
                }
              ];
            }
          )
        ];

        # 机器整个不可达时,它上面的 unit failed / 磁盘 / 温度告警全都会
        # 跟着触发(或者说,全都会因为抓不到而变成陈旧数据)。这条让
        # HostUnreachable 把同一台机器上的其它告警压下去,群里只看到
        # "tank 抓不到了"一条,而不是二十条。
        inhibit_rules = [
          {
            source_matchers = ["alertname = HostUnreachable"];
            target_matchers = ["severity =~ warning|info"];
            equal = ["instance"];
          }
        ];
      };
    };

    systemd.services.alertmanager = {
      after = ["network-online.target" "tailscaled.service"];
      wants = ["network-online.target" "tailscaled.service"];
      serviceConfig.RestartSec = "10s";
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

        # 经统一入口(./gateway.nix)进来的请求,Origin 是入口那台的地址,
        # 和这份 Grafana 自己的 root_url 对不上。Grafana 的 CSRF 中间件会
        # 因此拒掉所有 POST —— 症状很误导:面板打得开、菜单都正常,只有
        # 图表一片空白(查询走的是 POST /api/ds/query)。
        # 没有入口时是空表,这一项不会出现在 ini 里。
        security.csrf_trusted_origins = lib.mkIf (gateways != []) (
          lib.concatStringsSep " " (
            map (g: "${g.tsIp}:${toString cfg.grafanaPort}") gateways
          )
        );

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

      # 看板声明式下发,不靠手动 import。手动导入的看板只活在 grafana.db 里,
      # tank 一重装就没了 —— 那跟这个仓库其它东西的做法是拧着的。
      #
      # 但只放**现成货给不了的那张**:fleet 总览 + tailnet 延迟矩阵。像
      # 1860(Node Exporter Full)那种通用单机看板留着手动 import 就行,
      # 它是 250KB 生成出来的 JSON,为了省一次重装后的点击把它塞进仓库不划算。
      provision.dashboards.settings = {
        apiVersion = 1;
        providers = [
          {
            name = "nix";
            orgId = 1;
            type = "file";
            # 仓库是唯一事实来源,别让人从 UI 里删掉一个由 nix 管的看板 ——
            # 删了下次 rebuild 又会回来,只会让人困惑。
            disableDeletion = true;
            # 但允许在 UI 里改。想调 panel 就调,满意了 export JSON 覆盖回
            # 仓库里那份。设成 false 的话每次点编辑都被顶回去,很难用。
            allowUiUpdates = true;
            updateIntervalSeconds = 30;
            options = {
              path = ./dashboards;
              foldersFromFilesStructure = false;
            };
          }
        ];
      };

      provision.datasources.settings = {
        apiVersion = 1;

        # 先删同名的再建。
        #
        # 不加这个的话,给一个**已经存在于 grafana.db 里的**数据源改 uid 会让
        # provisioning 报 "data source not found" —— 它按新 uid 去找要更新的
        # 记录,而库里那条是旧的随机 uid。踩过一次:加上 `uid = "prometheus"`
        # 之后 Grafana 直接起不来了。
        #
        # **Grafana 把 provisioning 失败当致命错误,不是警告。** 数据源配错、
        # 看板 JSON 不合法,都会让整个服务拒绝启动 —— 症状是浏览器
        # "refused to connect",而 Prometheus 和 Alertmanager 还好好的,
        # 很容易往网络方向排查。
        #
        # 长期留着而不是手动删一次:tank 万一从旧的 grafana.db 恢复,同样的
        # 冲突会再来一遍。删掉再建对一个纯声明式的数据源没有任何代价 ——
        # 它不存查询、不存状态,uid 又是钉死的,看板的引用不会断。
        deleteDatasources =
          [
            {
              name = "Prometheus";
              orgId = 1;
            }
          ]
          ++ map (p: {
            name = "Prometheus (${p.name})";
            orgId = 1;
          })
          peers;

        datasources =
          [
            {
              name = "Prometheus";
              type = "prometheus";
              # 固定 uid。声明式下发的看板要在 JSON 里写死数据源引用,而 Grafana
              # 默认给的是随机 uid —— 那样看板每次重装都会指向一个不存在的数据源,
              # 打开是一片 "Datasource not found"。
              uid = "prometheus";
              access = "proxy";
              # **必须是 selfIp,不能"顺手优化"成 127.0.0.1。** Prometheus 只
              # 接受一个 listen 地址,而上面把它绑到了 tailscale 地址上,回环
              # 根本没有监听。同机通信绕一下 tailscale0 的开销可以忽略。
              url = "http://${selfIp}:${toString cfg.port}";
              isDefault = true;
            }
          ]
          ++ map (p: {
            # 另一份的数据。**两份抓的是同一批 target,所以平时它俩内容一样** ——
            # 加这个数据源不是为了看别的东西,是为了补上对方停机期间的那一段:
            # 那段时间只有活着的那份有数据。
            #
            # 于是无论你从哪份 Grafana 进去,都能把整条时间线看全,不用记
            # "上次停电时哪台还活着"。看板默认仍然读本地那个(uid = prometheus),
            # 要对比就在面板上换数据源。
            name = "Prometheus (${p.name})";
            type = "prometheus";
            # uid 带主机名。不能和本地那个抢 "prometheus" —— 声明式看板全都
            # 按那个 uid 引用数据源。
            uid = "prometheus-${p.name}";
            access = "proxy";
            url = "http://${p.tsIp}:${toString cfg.port}";
            isDefault = false;
          })
          peers;
      };
    };

    # 这个 fleet 现在 8 台全是 firewall.enable = false,下面两条是空转的。
    # 留着是为了模块自身正确:哪天某台把防火墙打开,监控不会莫名其妙失联。
    # 注意是 interfaces.tailscale0 而不是全局 allowedTCPPorts —— 只在
    # tailscale 接口上放行,不碰 WAN。
    networking.firewall.interfaces.tailscale0.allowedTCPPorts =
      [
        cfg.port
        cfg.grafanaPort
        cfg.alertmanagerPort
      ]
      ++ lib.optional (peers != []) clusterPort;

    # memberlist 的 gossip 同时用 TCP 和 UDP:TCP 做状态同步和推拉,UDP 做
    # 探活。只放 TCP 的话集群能建起来,但节点探活会一直超时,表现成成员时有
    # 时无 —— 比彻底连不上更难查。
    networking.firewall.interfaces.tailscale0.allowedUDPPorts =
      lib.optional (peers != []) clusterPort;

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
