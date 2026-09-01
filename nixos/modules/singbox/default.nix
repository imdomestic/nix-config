{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.my.singbox;

  # 节点凭据。这个文件按 .sops.yaml 的兜底 creation_rule 加密给全部 admin +
  # 全部 host，所以任何一台路由器都能解出全部节点,urltest 才有得挑。
  # 绝不能写死在这里 —— 本仓库是公开的。
  clientSecrets = ../../../secrets/clients/imdomestic.yaml;

  # 名单在 ../im-nodes.nix,和 modules/{imsub,mihomo} 共用一份。
  nodes = import ../im-nodes.nix;
  nodeFields = ["uuid" "public_key" "short_id"];

  # **每个出口一个 urltest,两个出口之间只手动切。** urltest 只比延迟,而这两条
  # 线延迟和吞吐是反的:悉尼延迟更低,吞吐却只有日本的 1/3 到 1/7(同一台 h610
  # 实测,见 docs/decisions.md#au-exit-separate-auto-group)。
  jpTags = map (n: "im-${n.name}") (lib.filter (n: n.exit == "jp") nodes);
  auTags = map (n: "im-${n.name}") (lib.filter (n: n.exit == "au") nodes);

  secretPath = node: field: config.sops.secrets."imdomestic/${node.secret}/${field}".path;

  # `_secret` 由 NixOS sing-box 模块的 ExecStartPre 处理:那一句带 `+` 前缀,
  # 以 root 运行 jq 把文件内容填进 /run/sing-box/config.json,再 chown 给
  # sing-box 用户。所以 /run/secrets 下这些文件保持 root-only 就够了。
  mkNode = node: {
    type = "vless";
    tag = "im-${node.name}";
    server = node.host;
    server_port = node.port;
    uuid._secret = secretPath node "uuid";
    flow = "xtls-rprx-vision";
    packet_encoding = "xudp";
    tls = {
      enabled = true;
      server_name = "www.aliyun.com";
      utls = {
        enabled = true;
        fingerprint = "chrome";
      };
      reality = {
        enabled = true;
        public_key._secret = secretPath node "public_key";
        short_id._secret = secretPath node "short_id";
      };
    };
  };

  # sing-box 1.13 只认编译好的 .srs;旧的 geoip.db/geosite.db 格式已经删了。
  geositeDir = "${pkgs.sing-geosite}/share/sing-box/rule-set";
  geoipDir = "${pkgs.sing-geoip}/share/sing-box/rule-set";

  mkLocalRuleSet = dir: prefix: name: {
    type = "local";
    tag = "${prefix}-${name}";
    format = "binary";
    path = "${dir}/${prefix}-${name}.srs";
  };

  geositeNames = [
    "cn"
    "private"
    "bilibili"
    "steam"
    "steam@cn"
    "epicgames"
    "ea"
    "ubisoft"
    "apple"
    "apple@cn"
    "github"
    "microsoft"
    "category-ads-all"
    "discord"
    "google"
    "google@cn"
    "google-gemini"
    "telegram"
  ];
  # geoip 只装 cn:sing-geoip 里没有 geoip-private.srs,私网靠 ip_is_private 匹配。
  geoipNames = ["cn"];

  ruleSets =
    (map (mkLocalRuleSet geositeDir "geosite") geositeNames)
    ++ (map (mkLocalRuleSet geoipDir "geoip") geoipNames);

  toDirect = rule:
    rule
    // {
      action = "route";
      outbound = "direct";
    };
  toProxy = rule:
    rule
    // {
      action = "route";
      outbound = "im";
    };
in {
  options.my.singbox.autoRedirect = lib.mkOption {
    type = lib.types.bool;
    default = true;
    description = ''
      是否启用 tun 的 auto_redirect。上游一律推荐开(性能比 tproxy 好,还能把
      LAN 客户端发往路由器 53 端口的 DNS 一并 DNAT 进来),所以默认开。

      **但是 WAN 地址落在 100.64.0.0/10 的机器必须关掉。** auto_redirect 对
      本机发出的 TCP 是在 nat output 链里 `redirect to :<port>`,内核会把目的
      地址改写成 127.0.0.1 再从 lo 投递;此时源地址仍是 WAN 地址。而 tailscale
      在 filter INPUT 里挂了一条反欺骗规则:

          ip saddr 100.64.0.0/10 iifname != "tailscale0" drop

      电信 PPPoE 下发的正是 CGNAT 地址(r6s 拿到的是 100.84.115.12),于是本机
      自己发起的 IPv4 TCP 全部被这条规则吃掉——SYN 在 lo 上反复重传,没有 RST,
      沿途没有任何日志。IPv6 不受影响(tailscale 那条对应规则用的是
      fd7a:115c:a1e0::/48),LAN 转发流量也不受影响(prerouting 的 redirect
      改写成的是 br-lan 地址,源是 192.168.22.x)。所以症状是「只有路由器自己
      上不了 v4」,极具迷惑性。

      关掉之后走纯 auto_route 策略路由:本机和转发流量都进 tun0,不经 lo,
      也就不碰 tailscale 那条规则。代价是性能略低,以及 LAN 的 DNS 不再被
      DNAT——但本机 systemd-resolved 已经在 192.168.22.1:53 上服务 LAN,它的
      上游查询照样进 tun 被 hijack-dns 接管,分流策略不变,和之前 dae 的路径
      完全一样。
    '';
  };

  config.sops.secrets = lib.listToAttrs (lib.concatMap (node:
    map (field: {
      name = "imdomestic/${node.secret}/${field}";
      value = {
        sopsFile = clientSecrets;
        restartUnits = ["sing-box.service"];
      };
    })
    nodeFields)
  nodes);

  config.services.sing-box = {
    enable = true;
    settings = {
      log = {
        level = "info";
        timestamp = true;
      };

      dns = {
        # 1.13 必须用带 type 的新式 DNS server。旧的 {address = "..."} 在 1.13
        # 不是告警而是**直接 Fatal**:legacy DNS servers 定在 1.14 移除,而
        # deprecated.Impending() 在"距离移除只剩一个小版本"时就会 logger.Fatal。
        servers = [
          {
            tag = "alidns";
            type = "udp";
            server = "223.5.5.5";
          }
          # 境外域名走 8.8.8.8/TCP 且经 im 出去。dae 那边是"全都问 alidns,
          # 发现返回私网 IP 再改问 googledns"的事后纠偏;sing-box 没有 response
          # 规则,所以改成事前避免污染。detour 在 1.12+ 属于 dial 字段。
          {
            tag = "dns-proxy";
            type = "tcp";
            server = "8.8.8.8";
            detour = "im";
          }
        ];
        rules = [
          {
            rule_set = ["geosite-category-ads-all"];
            action = "reject";
          }
          # 自建域名必须用国内 DNS 解析,而且要排在最前面:im 的 outbound
          # 全是 *.imdomestic.com,如果它们的解析又绕回 dns-proxy(detour = im)
          # 就成了死循环,sing-box 起不来。
          {
            domain_suffix = ["imdomestic.com"];
            action = "route";
            server = "alidns";
          }
          {
            rule_set = [
              "geosite-cn"
              "geosite-private"
              "geosite-google@cn"
              "geosite-apple@cn"
            ];
            action = "route";
            server = "alidns";
          }
        ];
        final = "dns-proxy";
        strategy = "prefer_ipv4";
      };

      inbounds = [
        {
          type = "tun";
          tag = "tun-in";
          # /30 和 /126 不是随便写的:auto_redirect 那条"劫持发往本机 53 端口"
          # 的 nftables DNAT 规则,目标地址取的是 tun 地址 +1(172.19.0.2)。
          # 写成 /32 就没有 +1 可用,规则会被静默跳过,LAN 的 DNS 一条都不劫持。
          # 同理没有 v6 地址就不会生成 v6 的劫持规则,而本机 LAN 是 SLAAC。
          address = ["172.19.0.1/30" "fdfe:dcba:9876::1/126"];
          auto_route = true;
          # 见 my.singbox.autoRedirect 的说明:开着更好,但 WAN 是 CGNAT 地址
          # 的机器会撞上 tailscale 的反欺骗规则,只能关。
          auto_redirect = cfg.autoRedirect;
          strict_route = true;
          stack = "system";
          # tailscale 整段不进 tun。这是唯一不依赖代理的回退通道 —— 一旦
          # sing-box 配错,还得靠它 ssh 进来回滚。route_exclude_address 在
          # auto_redirect 的 nftables 路径里同样生效(nftablesCreateExcludeDestinationIPSet)。
          route_exclude_address = ["100.64.0.0/10" "fd7a:115c:a1e0::/48"];
        }
      ];

      outbounds =
        [
          # route 的落点是 `im`(final = "im"),所以它得是 selector:默认走
          # 列表第一个 auto-jp,要换出口就在客户端里选 auto-au。
          {
            type = "selector";
            tag = "im";
            outbounds = ["auto-jp" "auto-au"] ++ jpTags ++ auTags;
          }
          {
            type = "urltest";
            tag = "auto-jp";
            outbounds = jpTags;
            url = "http://cp.cloudflare.com/generate_204";
            interval = "3m";
            tolerance = 50;
          }
          {
            type = "urltest";
            tag = "auto-au";
            outbounds = auTags;
            url = "http://cp.cloudflare.com/generate_204";
            interval = "3m";
            tolerance = 50;
          }
        ]
        ++ map mkNode nodes
        ++ [
          {
            type = "direct";
            tag = "direct";
          }
        ];

      route = {
        # 1.13 里配了两个及以上 DNS server 又不给 default_domain_resolver,
        # 同样是 Fatal(missing domain resolver 也进了 impending deprecation)。
        default_domain_resolver = {server = "alidns";};
        rule_set = ruleSets;
        rules = [
          {action = "sniff";}
          {
            protocol = "dns";
            action = "hijack-dns";
          }

          # --- tailscale 直连 ---
          # 注意 process_name 只对本机进程有效:sing-box 只在源地址等于本机
          # 某个接口地址时才查 /proc,LAN 客户端的转发流量永远匹配不上。
          # tailscaled 跑在本机,所以这条是有意义的;dae 里那些 pname(qq,
          # wechat, git) 规则对路由器来说本来就是空转,没有照搬。
          (toDirect {ip_cidr = ["100.100.100.100/32" "100.64.0.0/10" "fd7a:115c:a1e0::/48"];})
          (toDirect {source_port = [41641];})
          (toDirect {port = [41641];})
          (toDirect {process_name = ["tailscaled" "tailscale"];})

          # --- 自建基础设施直连 ---
          # dae 里对应 `domain(suffix: imdomestic.com) -> must_direct`。
          # 少了这条,末尾的 final = im 会把 ssh 到 <host>.imdomestic.com 也丢进
          # im 组,而 im 组本身就是 portal -> 反向隧道 -> r5sjp;隧道一断,
          # 用来修隧道的 ssh 跟着断,没法回滚。
          (toDirect {domain_suffix = ["imdomestic.com"];})

          # --- 国内 DNS / 组播 / 私网 ---
          (toDirect {ip_cidr = ["223.5.5.5/32" "223.6.6.6/32" "119.29.29.29/32" "224.0.0.0/4" "ff00::/8"];})
          (toDirect {ip_is_private = true;})

          (toDirect {rule_set = ["geosite-cn" "geoip-cn" "geosite-bilibili"];})

          # Steam:下载/内容走直连,商店和社区走代理
          (toDirect {domain_suffix = ["cm.steampowered.com" "steamserver.net" "steamcontent.com"];})
          (toDirect {rule_set = ["geosite-steam@cn"];})
          (toProxy {rule_set = ["geosite-steam"];})

          (toDirect {rule_set = ["geosite-epicgames" "geosite-ea" "geosite-ubisoft"];})
          (toDirect {rule_set = ["geosite-apple@cn" "geosite-apple"];})
          (toProxy {rule_set = ["geosite-github"];})
          (toDirect {rule_set = ["geosite-microsoft"];})

          {
            rule_set = ["geosite-category-ads-all"];
            action = "reject";
          }

          (toProxy {
            rule_set = [
              "geosite-discord"
              "geosite-google-gemini"
              "geosite-google"
              "geosite-telegram"
            ];
          })
        ];
        final = "im";
        auto_detect_interface = true;
      };

      experimental.cache_file.enabled = true;
    };
  };
}
