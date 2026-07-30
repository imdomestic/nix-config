{
  config,
  lib,
  pkgs,
  ...
}: let
  # 五台 portal 的 client-in2 凭据。这个文件按 .sops.yaml 的兜底 creation_rule
  # 加密给全部 admin + 全部 host，所以任何一台路由器都能解出全部五个节点,
  # urltest 才有得挑。绝不能写死在这里 —— 本仓库是公开的。
  clientSecrets = ../../../secrets/clients/imdomestic.yaml;

  # <name>.imdomestic.com:54322 = 各 portal 的 client-in2 入口。
  # r2s 不在列:长期离线,已从 r5sjp 摘掉 bridge,而且那条 DNS 记录现在多半
  # 指向别人的设备(见 docs/proxy-todo.md)。
  nodeNames = ["h610" "rpi4" "sh" "r5s" "r6s"];
  nodeTags = map (n: "im-${n}") nodeNames;
  nodeFields = ["uuid" "public_key" "short_id"];

  secretPath = node: field: config.sops.secrets."imdomestic/${node}/${field}".path;

  # `_secret` 由 NixOS sing-box 模块的 ExecStartPre 处理:那一句带 `+` 前缀,
  # 以 root 运行 jq 把文件内容填进 /run/sing-box/config.json,再 chown 给
  # sing-box 用户。所以 /run/secrets 下这些文件保持 root-only 就够了。
  mkNode = name: {
    type = "vless";
    tag = "im-${name}";
    server = "${name}.imdomestic.com";
    server_port = 54322;
    uuid._secret = secretPath name "uuid";
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
        public_key._secret = secretPath name "public_key";
        short_id._secret = secretPath name "short_id";
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

  toDirect = rule: rule // {action = "route"; outbound = "direct";};
  toProxy = rule: rule // {action = "route"; outbound = "im";};
in {
  sops.secrets = lib.listToAttrs (lib.concatMap (node:
    map (field: {
      name = "imdomestic/${node}/${field}";
      value = {
        sopsFile = clientSecrets;
        restartUnits = ["sing-box.service"];
      };
    })
    nodeFields)
  nodeNames);

  services.sing-box = {
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
          # 自建域名必须用国内 DNS 解析,而且要排在最前面:im 的五个 outbound
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
          # auto_redirect 在 Linux 上不是可选项:它用 nftables 在 prerouting
          # 做 DNAT,既接管 LAN 转发流量,也是"LAN 客户端把 192.168.22.1 当 DNS"
          # 这种本机目的流量唯一会被劫持的路径(本机目的走 local 表,优先级 0,
          # 根本轮不到 auto_route 在 9000+ 的策略路由)。
          auto_redirect = true;
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
          {
            type = "urltest";
            tag = "im";
            outbounds = nodeTags;
            url = "http://cp.cloudflare.com/generate_204";
            interval = "3m";
            tolerance = 50;
          }
        ]
        ++ map mkNode nodeNames
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
