{
  pkgs,
  ...
}: let
  # Rule-set databases shipped as local .srs files (sing-box 1.13 removed the
  # legacy geoip/geosite db format, so we reference compiled rule-sets instead).
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
    "google-gemini"
    "google"
    "telegram"
  ];
  geoipNames = ["cn"];

  ruleSets =
    (map (mkLocalRuleSet geositeDir "geosite") geositeNames)
    ++ (map (mkLocalRuleSet geoipDir "geoip") geoipNames);

  # Self-built imdomestic reality nodes (the `im` group from the old dae config).
  # Shared across every soft router; the local node is harmless in the urltest.
  mkNode = name: {
    type = "vless";
    tag = "im-${name}";
    server = "${name}.imdomestic.com";
    server_port = 54321;
    uuid = "2cac4128-2151-4a28-8102-ea1806f9c12b";
    flow = "xtls-rprx-vision";
    packet_encoding = "xudp";
    tls = {
      enabled = true;
      server_name = "www.microsoft.com";
      utls = {
        enabled = true;
        fingerprint = "chrome";
      };
      reality = {
        enabled = true;
        public_key = "2oMfAnRmOiZN3ra85D05Zhr8ehI8hRSRqzpJ0oJUcgM";
        short_id = "16";
      };
    };
  };

  nodeNames = ["h610" "rpi4" "sh" "r5s" "r6s" "r2s"];
  nodeTags = map (n: "im-${n}") nodeNames;
  nodeOutbounds = map mkNode nodeNames;
in {
  services.sing-box = {
    enable = true;
    settings = {
      log = {
        level = "info";
        timestamp = true;
      };

      dns = {
        servers = [
          {
            tag = "alidns";
            type = "udp";
            server = "223.5.5.5";
          }
          {
            tag = "google";
            type = "tcp";
            server = "8.8.8.8";
            detour = "im";
          }
        ];
        rules = [
          {
            rule_set = ["geosite-cn"];
            server = "alidns";
          }
        ];
        # final = "google";
        final = "alidns";
        strategy = "prefer_ipv4";
      };

      inbounds = [
        {
          type = "tun";
          tag = "tun-in";
          address = ["172.19.0.1/30" "fdfe:dcba:9876::1/126"];
          auto_route = true;
          auto_redirect = true;
          strict_route = true;
          stack = "system";
        }
      ];

      outbounds =
        [
          {
            type = "selector";
            tag = "proxy";
            outbounds = ["im"] ++ nodeTags;
            default = "im";
          }
          {
            type = "urltest";
            tag = "im";
            outbounds = nodeTags;
            url = "https://www.gstatic.com/generate_204";
            interval = "3m";
            tolerance = 50;
          }
        ]
        ++ nodeOutbounds
        ++ [
          {
            type = "direct";
            tag = "direct";
          }
        ];

      route = {
        default_domain_resolver = {server = "alidns";};
        rule_set = ruleSets;
        rules = [
          {action = "sniff";}
          {
            protocol = "dns";
            action = "hijack-dns";
          }

          # tailscale & link-local -> direct
          {
            ip_cidr = ["100.100.100.100/32" "100.64.0.0/10" "fd7a:115c:a1e0::/48"];
            action = "route";
            outbound = "direct";
          }
          {
            source_port = [41641];
            action = "route";
            outbound = "direct";
          }
          {
            port = [41641];
            action = "route";
            outbound = "direct";
          }
          {
            process_name = ["tailscaled"];
            action = "route";
            outbound = "direct";
          }

          # CN DNS servers & multicast -> direct
          {
            ip_cidr = ["223.5.5.5/32" "223.6.6.6/32" "119.29.29.29/32" "224.0.0.0/4" "ff00::/8"];
            action = "route";
            outbound = "direct";
          }

          {
            ip_is_private = true;
            action = "route";
            outbound = "direct";
          }

          {
            rule_set = ["geosite-cn" "geoip-cn" "geosite-bilibili"];
            action = "route";
            outbound = "direct";
          }

          # Steam: content/CN direct, store/community proxied
          {
            domain_suffix = ["cm.steampowered.com" "steamserver.net" "steamcontent.com"];
            action = "route";
            outbound = "direct";
          }
          {
            rule_set = ["geosite-steam@cn"];
            action = "route";
            outbound = "direct";
          }
          {
            rule_set = ["geosite-steam"];
            action = "route";
            outbound = "im";
          }

          {
            rule_set = ["geosite-epicgames" "geosite-ea" "geosite-ubisoft"];
            action = "route";
            outbound = "direct";
          }

          {
            rule_set = ["geosite-apple@cn" "geosite-apple"];
            action = "route";
            outbound = "direct";
          }

          {
            rule_set = ["geosite-github"];
            action = "route";
            outbound = "im";
          }

          {
            rule_set = ["geosite-microsoft"];
            action = "route";
            outbound = "direct";
          }

          {
            rule_set = ["geosite-category-ads-all"];
            action = "reject";
          }

          {
            rule_set = ["geosite-discord" "geosite-google-gemini" "geosite-google" "geosite-telegram"];
            action = "route";
            outbound = "im";
          }
        ];
        final = "im";
        auto_detect_interface = true;
      };

      experimental.cache_file.enabled = true;
    };
  };
}
