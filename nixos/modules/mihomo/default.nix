{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.my.mihomo;

  # 五台 portal 的 client-in2 凭据,和 modules/singbox 用的是同一个 sops 文件
  # (加密给全部 admin + 全部 host)。r2s 不在列:长期离线,已从 r5sjp 摘掉
  # bridge,而且那条 DNS 记录现在多半指向别人的设备,见 docs/proxy-todo.md。
  nodeNames = ["h610" "rpi4" "sh" "r5s" "r6s"];
  nodeFields = ["uuid" "public_key" "short_id"];
  s = config.sops.placeholder;
  sec = node: field: s."imdomestic/${node}/${field}";

  mkProxy = node: {
    name = "imdomestic-${node}";
    type = "vless";
    server = "${node}.imdomestic.com";
    port = 54322;
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

  nodeTags = map (n: "imdomestic-${n}") nodeNames;

  # 主策略组的类型。smart 是 vernesong fork 独有的,上游 mihomo 会直接报
  # `unsupported type: smart` 而拒绝启动 —— 所以这两个开关必须一起动,
  # 不能只开一个。
  autoGroup =
    {
      name = "auto";
      proxies = nodeTags;
      url = "http://cp.cloudflare.com/generate_204";
      interval = 300;
      tolerance = 100;
    }
    // (
      if cfg.smart
      then {
        type = "smart";
        # 显式关掉。开了它会在运行时从网上下载 Model.bin;关掉走内置评分,
        # 用 latency + lossRate,后者取自内核 TCP_INFO 的 tcpi_total_retrans。
        # 那正是我们需要的量 —— 实测 h610 那条链路 RTT 89ms 看着健康,但
        # 吞吐只有 4.8 Mbit/s、丢包 13%,纯延迟指标分辨不出来。
        uselightgbm = false;
      }
      else {type = "url-test";}
    );
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
    sops.secrets = lib.listToAttrs (lib.concatMap (node:
      map (field: {
        name = "imdomestic/${node}/${field}";
        value = {
          sopsFile = ../../../secrets/clients/imdomestic.yaml;
          restartUnits = ["mihomo.service"];
        };
      })
      nodeFields)
    nodeNames);

    # 整份配置由 sops 渲染。里面有五个节点的 UUID 和 Reality 公钥,内联进
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
        external-controller = "127.0.0.1:9090";

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

        dns = {
          enable = true;
          ipv6 = true;
          listen = "0.0.0.0:1053";
          enhanced-mode = "fake-ip";
          fake-ip-range = "198.18.0.1/16";
          # 自建域名不能进 fake-ip:下面 imdomestic.com 走 DIRECT,需要真实 IP。
          fake-ip-filter = ["*.imdomestic.com"];
          nameserver = ["223.5.5.5" "119.29.29.29"];
        };

        proxies = map mkProxy nodeNames;

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
            "AND,(NETWORK,UDP),(DST-PORT,443),REJECT"
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

            "GEOSITE,github,im"
            "GEOSITE,google-gemini,im"
            "GEOSITE,google,im"
            "GEOSITE,telegram,im"

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
  };
}
