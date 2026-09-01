{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.my.mihomo;

  # 节点凭据,和 modules/singbox、modules/imsub 用的是同一个 sops 文件
  # (加密给全部 admin + 全部 host)。名单在 ../im-nodes.nix,三个模块共用一份。
  nodes = import ../im-nodes.nix;
  nodeFields = ["uuid" "public_key" "short_id"];
  s = config.sops.placeholder;
  sec = node: field: s."imdomestic/${node.secret}/${field}";

  mkProxy = node: {
    name = "imdomestic-${node.name}";
    type = "vless";
    server = node.host;
    inherit (node) port;
    uuid = sec node "uuid";
    network = "tcp";
    tls = true;
    udp = true;
    xudp = true;
    flow = "xtls-rprx-vision";
    servername = "www.aliyun.com";
    client-fingerprint = "chrome";
    reality-opts = {
      public-key = sec node "public_key";
      short-id = sec node "short_id";
    };
  };

  nodeTags = map (n: "imdomestic-${n.name}") nodes;

  # 自动组只收日本出口。悉尼那两个延迟更低、带宽却只有 1/9,而 url-test/smart
  # 只比延迟 —— 放进来它们会稳定胜出,然后把大文件传输拖垮。
  autoTags = map (n: "imdomestic-${n.name}") (lib.filter (n: n.exit == "jp") nodes);

  # 国外 DNS,经代理出去(respect-rules)。
  #
  # **用 tcp:// 而不是 tls://。** 流量已经在 VLESS 隧道里加密了,DoT 只是白白多
  # 一次 TLS 握手 —— 而这条跨境链路丢包严重(h610 实测 13%),多一次往返就经常
  # 超时。2026-07-31 h610 上就是栽在这:日志里全是
  # `dial im --> 1.1.1.1:853 error: ... operation was canceled`,fallback 一失败
  # 就退回国内 DNS 的结果,于是 chatgpt.com 被解析成 157.240.8.50(Facebook 的段),
  # cliproxy 连不上 OpenAI。dae 当初用的也是 `tcp+udp://dns.google.com:53`,没有 TLS。
  #
  # 不用 udp:// 是因为反向隧道(portal/bridge)对 UDP 支持差,这一点 dae 的配置
  # 注释里也写过。
  foreignDns = ["tcp://8.8.8.8" "tcp://1.1.1.1"];

  # 主策略组的类型。smart 是 vernesong fork 独有的,上游 mihomo 会直接报
  # `unsupported type: smart` 而拒绝启动 —— 所以这两个开关必须一起动,
  # 不能只开一个。
  autoGroup =
    {
      name = "auto";
      proxies = autoTags;
      url = "http://cp.cloudflare.com/generate_204";
      interval = 300;
      tolerance = 100;
    }
    // (
      if cfg.smart
      then {
        type = "smart";
        # 显式关掉。开了它会从 github.com/vernesong/mihomo/releases 下一个
        # 7.8MB 的 Model.bin,用纯 Go 的 leaves 做推理(不在本地训练,CPU 开销
        # 可以忽略)。问题不是跑不动,是那个模型是上游拿别人的流量训的通用模型,
        # 未必认得出我们这个具体形态 —— h610 那条链路 RTT 89ms 看着健康,但
        # 吞吐只有 4.8 Mbit/s、丢包 13%。关掉走内置评分,用 latency + lossRate,
        # 后者取自内核 TCP_INFO 的 tcpi_total_retrans,正是能区分开的那个量。
        uselightgbm = false;

        # 把每条连接的特征写成 CSV 存本地(不上传),将来可以拿它训一个针对
        # 我们自己链路的模型,再用 lgbm-url 指过去替掉上面那个通用模型。
        #
        # 落盘在 $HomeDir/smart_weight_data.csv,即 /var/lib/private/mihomo/。
        # 默认上限 100MB(smart-collector-size),超了就地截断,不会撑爆盘 ——
        # r6s 的 / 还剩 9.6G。
        #
        # 注意这个 CSV 里有 host_raw / ip_raw / asn_raw 三列,是明文的目标域名
        # 和 IP。等于在路由器上留了一份全家的上网记录,别顺手 rsync 出去。
        collectdata = true;
      }
      else {type = "url-test";}
    );

  # 拦 QUIC(UDP/443)。`sub` 为 null 时无条件拦,否则再 AND 上一条子规则。
  #
  # **拦它的唯一理由是逼客户端回退到 TCP** —— 反向隧道对 UDP 支持差。这个理由
  # 只对**最终要出国**的流量成立;对直连目标拦它是纯亏,而且 mihomo 的 REJECT
  # 对 UDP 是静默丢包,客户端只能干等 QUIC 超时。经过见
  # docs/incidents.md#quic-blackhole。
  #
  # 拆成多处而不是一条,是因为下面 DIRECT / im 的规则是交错的,没有单一插入点
  # 能把两者分开。
  quicReject = sub: let
    parts = ["(NETWORK,UDP)" "(DST-PORT,443)"] ++ lib.optional (sub != null) sub;
  in "AND,(${lib.concatStringsSep "," parts}),REJECT";
in {
  options.my.mihomo = {
    smart = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        用 vernesong 的 mihomo fork(pkgs/mihomo-smart),并把 auto 组的类型
        从 `url-test` 换成 `smart`。

        上游 mihomo、sing-box、dae 的选路都只看延迟,而我们踩的坑恰恰是
        「延迟正常但吞吐崩溃」。实测跨境链路:

            h610      RTT  89ms   吞吐 4.8 Mbit/s   丢包 13%
            shanghai  RTT  63ms   吞吐 220 Mbit/s   丢包 0.31%

        89ms 在任何延迟检查里都是健康的,所以按延迟选会持续把约 1/5 的流量
        送进一条基本不可用的路。smart 组的评分同时看 latency 和 lossRate。

        包和组类型必须一起换:上游二进制遇到 `type: smart` 会直接拒绝启动。
      '';
    };

    extraRules = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "插在默认规则之前的额外规则。";
    };

    controllerAddress = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "100.64.0.5:9090";
      description = ''
        对外开放 RESTful API + metacubexd 面板的地址,访问 http://<地址>/ui。
        留空(默认)则只绑 127.0.0.1,本机之外连不上。

        **只填 tailscale 地址,不要填 0.0.0.0。** 这几台路由器的
        `networking.firewall.enable` 都是 false,绑 0.0.0.0 等于把一个能改
        选路策略、能看到全部连接的 API 直接挂在公网 ppp0 上。API 本身有
        secret 保护,但那是最后一道而不是唯一一道。

        绑的是 tailscale 地址,所以 mihomo 必须在 tailscaled 之后启动,见下面
        systemd 那段的 after/wants。
      '';
    };

    router = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        这台是网关,要接管 LAN 客户端的转发流量,而不只是本机流量。

        打开 `auto-redirect`,它用 nftables 在 prerouting 做 DNAT,才能接管
        被转发的流量;`auto-route` 那套策略路由主要管本机发出的。

        **不要同时使用 `route-address-set` / `route-exclude-address-set`。**
        那两个(rule-set 形式)会让 mihomo 打开 sing-tun 的 AutoRedirectMarkMode
        (listener/sing_tun/server.go:468),而 mark mode 一开,output 链里就会多
        一条把本机 TCP 重定向到 lo 的规则(redirect_nftables.go:63 那个
        `if AutoRedirectMarkMode` 包着的 nftablesCreateRedirect)。重定向后源地址
        仍是 WAN 地址,而电信 PPPoE 给 r6s 的是 CGNAT 的 100.84.115.12,正好落在
        tailscale 那条 `ip saddr 100.64.0.0/10 iifname != "tailscale0" drop` 里,
        于是本机 IPv4 全挂 —— 没有 RST、没有日志,只在 lo 上看到 SYN 重传。
        sing-box 1.13 是无条件开 mark mode 的,所以那次一定踩;mihomo 默认不开,
        只要不碰那两个 `-set` 选项就没事。详见 docs/proxy-todo.md 第 5 节。

        下面用的是普通的 `route-exclude-address`(前缀列表),不触发 mark mode。
      '';
    };
  };

  config = {
    sops.secrets =
      {
        # 面板/API 的访问口令。只在开了 controllerAddress 时才有意义,但无条件
        # 声明更简单 —— 反正 check-sops 会保证它在 sops 文件里存在。
        "mihomo/api_secret" = {restartUnits = ["mihomo.service"];};
      }
      // lib.listToAttrs (lib.concatMap (node:
        map (field: {
          name = "imdomestic/${node.secret}/${field}";
          value = {
            sopsFile = ../../../secrets/clients/imdomestic.yaml;
            restartUnits = ["mihomo.service"];
          };
        })
        nodeFields)
      nodes);

    # 整份配置由 sops 渲染。里面有各节点的 UUID 和 Reality 公钥,内联进
    # `settings` 会同时写进这个公开仓库和 world-readable 的 nix store。
    # mihomo.service 是 DynamicUser + LoadCredential:systemd 先以 root 读取
    # 渲染结果再投给动态用户,所以 root-only 的 /run/secrets 够用。
    #
    # JSON 是 YAML 的子集,所以 toJSON 的产物 mihomo 直接能读。
    sops.templates."mihomo-config.yaml" = {
      restartUnits = ["mihomo.service"];
      content = builtins.toJSON {
        mixed-port = 7893;
        allow-lan = true;
        mode = "rule";
        log-level = "info";
        ipv6 = true;
        # 默认只绑回环;填了 controllerAddress 才对外(见那个选项的说明)。
        external-controller =
          if cfg.controllerAddress == null
          then "127.0.0.1:9090"
          else cfg.controllerAddress;
        secret = config.sops.placeholder."mihomo/api_secret";

        # geodata 从 nix store 提供,绝不能让它自己去下载。
        #
        # 2026-07-31 就是栽在这里:r6s 上 dae 停掉、mihomo 启动,日志停在
        # `Can't find GeoSite.dat, start download` —— 它要下 geodata,而这时
        # 唯一的代理刚被自己替换掉,下载卡死、服务起不来、全家断网。死锁。
        # dae 模块本来就有 `assets = [v2ray-geoip v2ray-domain-list-community]`,
        # 我写这个模块时漏了等价的东西。
        #
        # 注意 `mihomo -t` 不会触发下载,所以配置校验全绿也发现不了 ——
        # 「能解析」和「能启动」是两回事。
        geodata-mode = true; # 用 .dat 而不是 .metadb
        geo-auto-update = false;

        tun =
          {
            enable = true;
            stack = "system";
            auto-route = true;
            auto-detect-interface = true;
            dns-hijack = ["any:53"];
          }
          // lib.optionalAttrs cfg.router {
            # 接管 LAN 转发流量,见 my.mihomo.router 的说明。
            auto-redirect = true;
            # tailscale 整段不进 tun。到 r6s 的 ssh 走的就是 100.64.0.5,
            # 配错了还得靠它进来回滚,这条路不能断。
            # 用普通前缀列表而不是 route-exclude-address-set —— 后者会触发
            # AutoRedirectMarkMode,进而生成打死本机 IPv4 的 lo 重定向。
            route-exclude-address = ["100.64.0.0/10" "fd7a:115c:a1e0::/48"];
          };

        # redir-host 而不是 fake-ip。三个理由,都不是洁癖:
        #
        # 1. **mihomo 停掉后还能上网。** fake-ip 返回的 198.18.x.x 一旦被上游
        #    systemd-resolved 缓存,mihomo 一停这些地址就全成了死的,连本来能
        #    直连的国内站点也跟着不通。redir-host 给的是真实 IP,停了照样用。
        # 2. **不留指纹。** 198.18.0.0/15 是 RFC 2544 的基准测试保留段,正常
        #    网络里不该出现,看到就知道在跑代理。
        # 3. **LAN 设备自己开代理时不打架。** tun 上的 dns-hijack 会截下所有
        #    经过的 53 端口流量,包括 LAN 里某台机器自己的 clash 去问 223.5.5.5。
        #    fake-ip 模式下它拿回的是 r6s 的假 IP,会被它当成"真实 IP"记进自己
        #    那张表;要是它也用默认的 198.18.0.0/15,它的 tun 还会把 r6s 的假 IP
        #    当成自己的去反查,查出来是毫不相干的域名。redir-host 只给真实 IP,
        #    对下层而言和没有代理一样,叠加就没有语义冲突。
        #
        # 代价(机制决定,配置绕不过):IP->域名 的还原表是一张 4096 条的 LRU
        # (dns/enhancer.go:188),淘汰掉就只能退化成按 IP 匹配;CDN 上几十个域名
        # 共用一个 IP 时表是 last-writer-wins,反查可能串。fake-ip 每个域名一个
        # 独占假 IP,没这两个问题 —— 这是实打实的取舍,不是纯赚。
        #
        # 最要紧的是:redir-host 必须真的把域名解析对,拿到毒 IP 就会去连毒 IP。
        # 所以下面那套分流 + 投毒检测不是可选项,是它能安全工作的前提。
        dns = {
          enable = true;
          ipv6 = true;
          listen = "0.0.0.0:1053";
          enhanced-mode = "redir-host";

          # 默认走国内。
          nameserver = ["223.5.5.5" "119.29.29.29"];

          # 解析代理节点地址本身用的 DNS。节点都是 imdomestic.com 的域名、都在
          # 国内,必须直接解析,不能绕回代理 —— 否则是「要连代理得先问代理」的
          # 死循环。开了 respect-rules 之后这项非空是**强制**的,留空启动即报错
          # (config.go:1426)。
          proxy-server-nameserver = ["223.5.5.5" "119.29.29.29"];

          # DNS 查询本身也走路由规则,这样下面 fallback 那几个国外 DNS 才会
          # 经代理出去,而不是明文直连(直连必被投毒,那 fallback 就没意义了)。
          respect-rules = true;

          # 明确分流,对应 dae 的 `qname(geosite:cn,...) -> alidns`。
          nameserver-policy = {
            "geosite:cn,private,apple@cn,google@cn" = ["223.5.5.5" "119.29.29.29"];
            "geosite:geolocation-!cn" = foreignDns;
            # geosite 的分类表更新有滞后,chatgpt.com 这类较新的域名不一定在
            # geolocation-!cn 里,漏了就会落到默认的国内 DNS 上被投毒。显式钉住。
            "+.openai.com,+.chatgpt.com,+.oaistatic.com,+.oaiusercontent.com" = foreignDns;
          };

          # 投毒检测,对应 dae 的
          # `response { ip(geoip:private) && !qname(geosite:cn) -> googledns }`。
          # 国内 DNS 的答案如果落在 CN 段之外,就采信 fallback 的结果。
          fallback = foreignDns;
          fallback-filter = {
            geoip = true;
            geoip-code = "CN";
            # 240/4 是保留段,GFW 投毒常返回这类地址。
            ipcidr = ["240.0.0.0/4" "0.0.0.0/32"];
          };
        };

        proxies = map mkProxy nodes;

        proxy-groups = [
          {
            name = "im";
            type = "select";
            proxies = ["auto"] ++ nodeTags;
          }
          autoGroup
        ];

        rules =
          cfg.extraRules
          ++ [
            "GEOSITE,category-ads-all,REJECT"

            # 自建基础设施直连,必须排在兜底之前。没有这条的话,ssh 到
            # <host>.imdomestic.com 会被 MATCH,im 丢进代理,而 im 组本身就是
            # portal -> 反向隧道 -> r5sjp;于是隧道一断,用来修隧道的 ssh 也
            # 跟着断。dae 和 clash 两边都踩过,规则同源。
            "DOMAIN-SUFFIX,imdomestic.com,DIRECT"

            "IP-CIDR,100.100.100.100/32,DIRECT,no-resolve"
            "SRC-PORT,41641,DIRECT"
            "DST-PORT,41641,DIRECT"
            "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve"
            "IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve"
            "PROCESS-NAME,tailscaled,DIRECT"
            "PROCESS-NAME,tailscale,DIRECT"

            "IP-CIDR,223.5.5.5/32,DIRECT,no-resolve"
            "IP-CIDR,223.6.6.6/32,DIRECT,no-resolve"
            "IP-CIDR,119.29.29.29/32,DIRECT,no-resolve"
            "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve"
            "IP-CIDR6,ff00::/8,DIRECT,no-resolve"
            "GEOIP,private,DIRECT,no-resolve"

          ]
          # **QUIC 只在「这条流量最终要出国」时才拦。** 见上面 quicReject 的说明。
          # 每个 tag 生成两条:先拦掉它的 QUIC,再把它的 TCP 送进代理。两条写在
          # 一起是为了改不漏 —— 新增 `,im` 规则时照抄这个形状即可。
          ++ lib.concatMap (tag: [
            (quicReject "(GEOSITE,${tag})")
            "GEOSITE,${tag},im"
          ]) ["github" "google-gemini" "google" "telegram"]
          ++ [
            "GEOSITE,cn,DIRECT"
            "GEOSITE,bilibili,DIRECT"
            "GEOSITE,steam@cn,DIRECT"
            "GEOSITE,steam,DIRECT"
            "GEOSITE,epicgames,DIRECT"
            "GEOSITE,ea,DIRECT"
            "GEOSITE,ubisoft,DIRECT"
            "GEOSITE,apple@cn,DIRECT"
            "GEOSITE,apple,DIRECT"
            "GEOSITE,microsoft,DIRECT"
            "GEOIP,cn,DIRECT"

            # 到这里还没匹配上的都要走下面的 MATCH,im 出国,所以拦掉它们的 QUIC。
            (quicReject null)
            "MATCH,im"
          ];
      };
    };

    services.mihomo = {
      enable = true;
      package = lib.mkIf cfg.smart (pkgs.callPackage ../../../pkgs/mihomo-smart {});
      tunMode = true;
      # GEOSITE / PROCESS-NAME 规则需要这个权限。
      processesInfo = true;
      webui = pkgs.metacubexd;
      configFile = config.sops.templates."mihomo-config.yaml".path;
    };

    # DNS 必须真的流经 mihomo,否则整套分流都是空的。
    #
    # `dns-hijack` 只劫持**进入 tun** 的流量。而本机查 127.0.0.53 走的是回环、
    # LAN 客户端查 192.168.22.1:53 是本机目的地址,两者都不进 tun —— 于是查询
    # 直接落到 systemd-resolved 配的国内上游,google.com 拿回投毒结果
    # (实测解析到 157.240.7.20 这个 Facebook 的地址和 2001::1 这个 Teredo 前缀),
    # 然后 wget 卡死。dae 没这问题是因为它在 eBPF 层连本机查询一起拦。
    #
    # 把 resolved 的上游指向 mihomo:LAN 继续查 192.168.22.1:53,resolved 转发
    # 给 mihomo,由 mihomo 做 fake-ip 和分流。DHCP/RA 通告的东西一个都不用动。
    # FallbackDNS 保持不变 —— mihomo 挂了至少还能解析,代价是那时会拿到投毒
    # 结果,但那种状态下本来也上不了网。
    services.resolved.settings.Resolve.DNS = lib.mkIf cfg.router ["127.0.0.1:1053"];

    # 把 geodata 摆进 mihomo 的工作目录。上游模块跑的是
    # `mihomo -d /var/lib/private/mihomo`,而它会在那个目录里找 GeoSite.dat /
    # GeoIP.dat,找不到就联网下载(见上面 geo-auto-update 那段的说明)。
    #
    # 用 ExecStartPre 带 `+` 前缀以 root 执行:服务是 DynamicUser,普通
    # tmpfiles 规则在 StateDirectory 建好之前就跑了,时机对不上。软链而不是
    # 复制,这样包更新时自动跟着换。
    systemd.services.mihomo = {
      # 绑的是 tailscale 地址,tailscaled 没起来的话这个地址还不存在,bind 会失败。
      after = lib.optionals (cfg.controllerAddress != null) ["tailscaled.service"];
      wants = lib.optionals (cfg.controllerAddress != null) ["tailscaled.service"];

      # nixpkgs 的 mihomo 单元没有 Restart=,默认就是 Restart=no。mihomo 一崩
      # 就永远躺着,而在 router 模式下这等于整个局域网断网:resolved 被指到
      # 127.0.0.1:1053,mihomo 没了 DNS 就全瞎。2026-08-01 r6s 上崩了两次
      # (06:25 和 10:18,原因见 pkgs/mihomo-smart 的补丁),两次都是人发现不对
      # 劲手动 restart 才恢复的。
      #
      # startLimitIntervalSec = 0 关掉次数限制:配置写坏时它会一直 5 秒一次地
      # 重试刷日志,但对一台没人在旁边的路由器来说,「一直重试」严格优于
      # 「试几次就放弃、然后永久断网」。
      startLimitIntervalSec = 0;
      serviceConfig.Restart = "always";
      serviceConfig.RestartSec = "5s";

      serviceConfig.ExecStartPre = [
        "+${pkgs.writeShellScript "mihomo-geodata" ''
          set -eu
          d=/var/lib/private/mihomo
          mkdir -p "$d"
          ln -sf ${pkgs.v2ray-domain-list-community}/share/v2ray/geosite.dat "$d/GeoSite.dat"
          ln -sf ${pkgs.v2ray-geoip}/share/v2ray/geoip.dat "$d/GeoIP.dat"
        ''}"
      ];
    };
  };
}
