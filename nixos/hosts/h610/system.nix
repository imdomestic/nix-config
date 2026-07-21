{
  pkgs,
  pkgs-unstable,
  inputs,
  config,
  lib,
  ...
}: let
  matrixUpstream = "http://100.64.0.4:8008";
  wg = import ../../../lib/wgClient.nix {inherit pkgs;} {
    privateKeyFile = config.sops.secrets."wireguard/private_key".path;
    presharedKeyFile = config.sops.secrets."wireguard/preshared_key".path;
    address = "10.0.0.5/24";
  };
in {
  imports = [
    ../../modules/dae
    ../../modules/keyd
    # ../../modules/minecraft/wuxi.nix
  ];

  sops.secrets."wireguard/private_key".owner = "systemd-network";
  sops.secrets."wireguard/preshared_key".owner = "systemd-network";

  # Service secrets (were hand-placed under /var/lib/secrets).
  # acme (root, via systemd EnvironmentFile) and livekit/lk-jwt (LoadCredential)
  # read as root, so root-owned is enough. coturn is different: its
  # static-auth-secret-file is consumed by a `replace-secret` ExecStartPre that
  # runs as the turnserver user, so that secret must be owned by turnserver.
  sops.secrets."acme/cloudflare_env" = {};
  sops.secrets."coturn/static_auth_secret".owner = "turnserver";
  sops.secrets."livekit/keys_yaml" = {};

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.kernelPackages = pkgs.linuxPackages_latest;

  # This host is the deploy-rs build box; emulate aarch64 so it can build the
  # SBC (r6s/rpi4/r5s) closures locally before pushing them.
  boot.binfmt.emulatedSystems = ["aarch64-linux"];
  # boot.kernelParams = [
  #   "pcie_aspm=off"
  #   "i915.force_probe=!56a5"
  #   "xe.force_probe=56a5"
  #   "enable_guc=3"
  # ];
  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
    "net.core.default_qdisc" = "fq";
    "net.ipv4.tcp_congestion_control" = "bbr";
  };

  time.timeZone = "Asia/Hong_Kong";

  networking = {
    networkmanager.enable = false; # Easiest to use and most distros use this by default.
    useDHCP = false;
    useNetworkd = true;
    nftables = {
      enable = true;
      tables.router = {
        name = "mss-clamping";
        enable = true;
        family = "inet";
        content = ''
          chain postrouting {
            type filter hook forward priority 0; policy accept;

            oifname "ppp0" meta nfproto ipv4 tcp flags syn tcp option maxseg size set 1452
            oifname "ppp0" meta nfproto ipv6 tcp flags syn tcp option maxseg size set 1432
          }
        '';
      };
    };
    firewall = {
      enable = false;
      trustedInterfaces = ["br-lan"];
      interfaces."ppp0".allowedUDPPorts = [546];
      checkReversePath = false;
    };
  };

  services.pppd = {
    enable = true;
    peers = {
      telecom = {
        autostart = true;
        enable = true;
        config = ''
          plugin pppoe.so eno1
          user "051012664304"
          password "845747"

          # usepeerdns

          # 关键参数
          defaultroute    # 自动添加默认路由
          persist         # 断线重连
          maxfail 0       # 无限次重试
          holdoff 5       # 重试间隔
          noipdefault
          noauth
          hide-password
          lcp-echo-interval 30
          lcp-echo-failure 20
          lcp-echo-adaptive

          +ipv6
          ipv6cp-use-ipaddr

          mtu 1492
          mru 1492
        '';
      };
    };
  };

  systemd.network = {
    enable = true;

    # bridge
    netdevs."10-br-lan" = {
      netdevConfig = {
        Kind = "bridge";
        Name = "br-lan";
      };
    };

    # wireguard
    netdevs."40-wg0" = wg.netdev;
    networks."40-wg0" = wg.network;

    # LAN
    networks."20-lan-uplink" = {
      matchConfig.Name = "enp5s0";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    networks."20-wan-uplink" = {
      matchConfig.Name = "eno1";
      linkConfig.RequiredForOnline = "no";
      networkConfig = {
        LinkLocalAddressing = "no";
        DHCP = "no";
      };
    };

    networks."25-wan-ppp" = {
      matchConfig.Name = "ppp0";
      networkConfig = {
        IPv6AcceptRA = true;
        DHCP = "ipv6";
        # pppd installs the IPv4 (IPCP) address; keep it across networkd
        # restarts so `nixos-rebuild switch` doesn't flush it.
        KeepConfiguration = "yes";
      };
      linkConfig = {
        RequiredForOnline = "carrier";
      };
      dhcpV6Config = {
        WithoutRA = "solicit";
        PrefixDelegationHint = "::/60";
        UseDelegatedPrefix = true;
      };
    };

    networks."30-br-lan" = {
      matchConfig.Name = "br-lan";
      networkConfig = {
        Address = "10.0.1.1/24";
        DHCPServer = true;
        IPMasquerade = "ipv4";

        IPv6SendRA = true;
        IPv6AcceptRA = false;
        DHCPPrefixDelegation = true;
      };
      linkConfig = {
        RequiredForOnline = "no"; # carrier
      };

      dhcpServerConfig = {
        PoolOffset = 100;
        PoolSize = 100;
        EmitDNS = true;
        DNS = ["10.0.1.1"];
      };

      # SLAAC
      ipv6SendRAConfig = {
        Managed = false; # no DHCPv6
        OtherInformation = false;
        EmitDNS = true; # send DNS with RA
      };
    };
  };

  systemd.tmpfiles.rules = [
    "d /var/lib/coturn 0750 root turnserver -"
  ];

  services.dnsmasq.enable = false;
  services.resolved = {
    enable = true;
    settings.Resolve = {
      FallbackDNS = ["223.5.5.5"];
      DNSStubListener = "yes";
      DNSStubListenerExtra = ["10.0.1.1" "::"];
    };
  };

  security.acme = {
    acceptTerms = true;
    defaults.email = "hankchogan@gmail.com";
  };

  security.acme.certs."tailscale.imdomestic.com" = {
    dnsProvider = "cloudflare";
    environmentFile = config.sops.secrets."acme/cloudflare_env".path;
    group = "nginx";
  };

  security.acme.certs."matrix.imdomestic.com" = {
    dnsProvider = "cloudflare";
    environmentFile = config.sops.secrets."acme/cloudflare_env".path;
    group = "nginx";
  };

  security.acme.certs."rtc.imdomestic.com" = {
    dnsProvider = "cloudflare";
    environmentFile = config.sops.secrets."acme/cloudflare_env".path;
    group = "nginx";
    reloadServices = [
      "nginx.service"
      "coturn.service"
    ];
  };

  # ddns-go cloudflare token + web password rendered from sops.
  sops.secrets."ddns/cloudflare_token" = {};
  sops.secrets."ddns/web_password" = {};
  sops.templates."ddns-go-config.yaml" = {
    restartUnits = ["ddns-go.service"];
    content = ''
      dnsconf:
          - name: "h610"
            ipv4:
              enable: true
              gettype: netInterface
              url: https://myip.ipip.net, https://ddns.oray.com/checkip, https://ip.3322.net, https://4.ipw.cn, https://v4.yinghualuo.cn/bejson
              netinterface: ppp0
              cmd: ""
              domains:
                  - h610:imdomestic.com
                  - tailscale:imdomestic.com
                  - matrix:imdomestic.com
                  - rtc:imdomestic.com
            ipv6:
              enable: true
              gettype: netInterface
              url: https://speed.neu6.edu.cn/getIP.php, https://v6.ident.me, https://6.ipw.cn, https://v6.yinghualuo.cn/bejson
              netinterface: ppp0
              cmd: ""
              ipv6reg: ""
              domains:
                  - matrix:imdomestic.com
                  - rtc:imdomestic.com
            dns:
              name: cloudflare
              id: ""
              secret: ${config.sops.placeholder."ddns/cloudflare_token"}
            ttl: ""
      user:
          username: hank
          password: ${config.sops.placeholder."ddns/web_password"}
      webhook:
          webhookurl: ""
          webhookrequestbody: ""
          webhookheaders: ""
      notallowwanaccess: false
      lang: zh
    '';
  };

  systemd.services.ddns-go = {
    enable = true;
    description = "ddns-go";

    wantedBy = ["multi-user.target"];
    wants = ["network-online.target"];
    after = ["network-online.target"];

    serviceConfig = {
      ExecStart = "${pkgs.ddns-go.outPath}/bin/ddns-go -f 300 -c ${config.sops.templates."ddns-go-config.yaml".path}";
      Restart = "always";
      RestartSec = 5;
    };
  };

  services.xray.enable = true;
  services.xray.settings = {
    log.loglevel = "warning";

    reverse = {
      portals = [
        {
          tag = "portal-h610";
          domain = "reverse-h610.hank.internal";
        }
      ];
    };

    inbounds = [
      {
        tag = "interconn";
        port = 1443;
        protocol = "vless";
        settings = {
          clients = [
            {
              id = "2cac4128-2151-4a28-8102-ea1806f9c12b";
              flow = "xtls-rprx-vision";
            }
          ];
          decryption = "none";
        };
        streamSettings = {
          network = "tcp";
          security = "reality";
          realitySettings = {
            show = false;
            dest = "www.apple.com:443";
            serverNames = ["www.apple.com" "apple.com"];
            privateKey = "SFXrsyrENIJqHMgk9Chjc-cA4MlzaTOBlF9OBAuSY0w";
            shortIds = ["16"];
          };
        };
      }

      # 2) 你的入口（示例：本机 socks）
      # {
      #   tag = "socks-in";
      #   port = 10800;
      #   protocol = "socks";
      #   settings = {
      #     auth = "noauth";
      #     udp = true;
      #   };
      # }

      {
        tag = "client-in";
        port = 54321;
        protocol = "vless";
        settings = {
          clients = [
            {
              id = "2cac4128-2151-4a28-8102-ea1806f9c12b";
              flow = "xtls-rprx-vision";
            }
          ];
          decryption = "none";
        };
        streamSettings = {
          network = "tcp";
          security = "reality";
          realitySettings = {
            show = false;
            dest = "www.apple.com:443";
            serverNames = ["www.apple.com" "apple.com"];
            privateKey = "SFXrsyrENIJqHMgk9Chjc-cA4MlzaTOBlF9OBAuSY0w";
            shortIds = ["16"];
          };
        };
      }
    ];

    outbounds = [
      {
        tag = "direct";
        protocol = "freedom";
      }
    ];

    routing.rules = [
      # {
      #   type = "field";
      #   inboundTag = ["socks-in"];
      #   outboundTag = "portal-h610";
      # }

      {
        type = "field";
        inboundTag = ["interconn"];
        outboundTag = "portal-h610";
      }

      {
        type = "field";
        inboundTag = ["client-in"];
        outboundTag = "portal-h610";
      }
    ];
  };

  services.displayManager.gdm.enable = false;
  services.desktopManager.gnome.enable = false;

  services.cockpit.enable = lib.mkForce false;

  services.ollama = {
    enable = true;
    package = pkgs-unstable.ollama-vulkan;
  };

  users.users.turnserver.extraGroups = ["nginx"];

  programs.zsh = {
    enable = true;
  };

  programs.nix-ld.enable = true;

  xdg.portal.wlr.enable = true;

  hardware.enableRedistributableFirmware = true;
  hardware.graphics = {
    enable = true;
    extraPackages = with pkgs; [
      vpl-gpu-rt
      intel-compute-runtime
      intel-media-driver
      mesa
    ];
    enable32Bit = true;
  };
  users.users.hank.extraGroups = ["video" "render" "docker"];

  # max bot: the Haskell code shells out to the real docker CLI and the
  # napcat compose file relies on host-gateway, so use Docker here rather
  # than the podman/dockerCompat setup other hosts use.
  virtualisation.docker.enable = true;
  # The host resolv.conf points at the systemd-resolved stub, so docker
  # falls back to 8.8.8.8 — which resolves CN sites to overseas CDNs that
  # don't load from here. Pin domestic resolvers for containers instead.
  virtualisation.docker.daemon.settings.dns = ["223.5.5.5" "119.29.29.29"];

  # max QQ bot (module from the max flake). The yaml is full of LLM API
  # keys, so it lives on disk under /var/lib/max-bot rather than in
  # `settings` (world-readable store).
  services.max-bot = {
    enable = true;
    configFile = "/var/lib/max-bot/max.yaml";
    environmentFile = "/var/lib/max-bot/max-bot.env"; # MAX_ACCESS_TOKEN
    napcat = {
      enable = true;
      qq = "2107570581";
      environmentFiles = ["/var/lib/max-bot/napcat.env"]; # NAPCAT_ACCESS_TOKEN
    };
  };
  # headscale owns 127.0.0.1:8080, so bind the OneBot WS on the docker
  # bridge only; napcat reaches it via host.docker.internal (host-gateway).
  systemd.services.max-bot.environment.MAX_WS_HOST = "172.17.0.1";

  environment = {
    variables = {
      EDITOR = "nvim";
    };
  };

  environment.systemPackages = with pkgs; [
    gcc
    neovim
    nginx
    intel-gpu-tools
    deploy-rs
    docker-compose
  ];

  environment.sessionVariables = {
    LIBVA_DRIVER_NAME = "iHD";
    NIXOS_OZONE_WL = "1";
  };
  xdg.portal.config.common.default = "*";

  services.openssh.enable = true;
  services.tailscale.enable = true;

  services.headscale = {
    enable = true;
    address = "127.0.0.1";
    port = 8080;
    settings = {
      policy.path = "${pkgs.writeText "headscale-policy.json" (builtins.toJSON {
        groups = {
          "group:imdomestic" = [
            "hank@imdomestic.com"
            "linwhite@imdomestic.com"
            "fendada@imdomestic.com"
            "kenneth@imdomestic.com"
          ];
        };

        acls = [
          # 核心规则：允许这个组内的所有人访问该组内的所有设备（所有端口）
          {
            action = "accept";
            src = ["group:imdomestic"];
            dst = ["group:imdomestic:*"];
          }

          # (可选) 允许所有人访问你广播的特定子网（比如你家的 R6S 局域网）
          # {
          #   action = "accept";
          #   src = [ "group:friends" ];
          #   dst = [ "192.168.1.0/24:*" ];
          # }
        ];
      })}";
      server_url = "https://tailscale.imdomestic.com:8443";
      derp.server = {
        enabled = true;
        region_id = 610;
        region_code = "h610";
        region_name = "H610";
        stun_listen_addr = "0.0.0.0:3479";
      };
      dns = {
        base_domain = "inner.imdomestic.com";
        magic_dns = true;
        nameservers = {};
        override_local_dns = false;
      };
      ip_prefixes = ["100.64.0.0/10"];
    };
  };

  # services.headplane = {
  #   enable = true;
  #   debug = true;
  #   settings = {
  #     server = {
  #       host = "127.0.0.1";
  #       port = 3000;
  #       base_url = "https://tailscale.imdomestic.com:8443";
  #       cookie_secure = true;
  #       cookie_secret_path = "/var/lib/secrets/headplane/cookie_secret";
  #     };
  #     headscale = {
  #       url = "http://127.0.0.1:8080";
  #       public_url = "https://tailscale.imdomestic.com:8443";
  #     };
  #     integration = {
  #       agent = {
  #         enabled = false;
  #         pre_authkey_path = "/var/lib/secrets/headplane/agent_preauthkey";
  #       };
  #       proc.enabled = true;
  #     };
  #   };
  # };

  services.coturn = {
    enable = true;
    no-cli = true;
    use-auth-secret = true;
    static-auth-secret-file = config.sops.secrets."coturn/static_auth_secret".path;
    realm = "rtc.imdomestic.com";
    cert = "/var/lib/acme/rtc.imdomestic.com/fullchain.pem";
    pkey = "/var/lib/acme/rtc.imdomestic.com/key.pem";
    listening-port = 3478;
    alt-listening-port = 3480;
    tls-listening-port = 5349;
    alt-tls-listening-port = 5351;
    min-port = 49152;
    max-port = 49999;
  };

  services.livekit = {
    enable = true;
    keyFile = config.sops.secrets."livekit/keys_yaml".path;
    settings = {
      port = 7880;
      room.auto_create = false;
      rtc = {
        tcp_port = 7881;
        port_range_start = 50000;
        port_range_end = 51000;
        use_external_ip = true;
      };
    };
  };

  services.lk-jwt-service = {
    enable = true;
    keyFile = config.sops.secrets."livekit/keys_yaml".path;
    port = 8088;
    livekitUrl = "wss://rtc.imdomestic.com:8448/livekit/sfu";
  };

  systemd.services.lk-jwt-service = {
    wants = ["livekit.service"];
    after = ["livekit.service"];
    environment.LIVEKIT_FULL_ACCESS_HOMESERVERS = "imdomestic.com";
  };

  services.nginx = {
    enable = true;
    clientMaxBodySize = "50m";
  };
  services.nginx.virtualHosts."tailscale.imdomestic.com" = {
    serverName = "tailscale.imdomestic.com";
    useACMEHost = "tailscale.imdomestic.com";
    forceSSL = true;
    http2 = true;
    listen = [
      {
        addr = "0.0.0.0";
        port = 8443;
        ssl = true;
      }
      {
        addr = "[::]";
        port = 8443;
        ssl = true;
      }
    ];
    locations."/" = {
      proxyPass = "http://127.0.0.1:8080";
      proxyWebsockets = true;
      extraConfig = ''
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
      '';
    };
    # locations."= /admin" = {
    #   extraConfig = ''
    #     return 302 /admin/;
    #   '';
    # };
    # locations."/admin/" = {
    #   proxyPass = "http://127.0.0.1:3000";
    #   proxyWebsockets = true;
    #   extraConfig = ''
    #     proxy_set_header Host $host;
    #     proxy_set_header X-Real-IP $remote_addr;
    #     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    #     proxy_set_header X-Forwarded-Proto $scheme;
    #     proxy_read_timeout 3600s;
    #     proxy_send_timeout 3600s;
    #   '';
    # };
  };
  services.nginx.virtualHosts."matrix.imdomestic.com" = {
    serverName = "matrix.imdomestic.com";
    useACMEHost = "matrix.imdomestic.com";
    addSSL = true;
    http2 = true;
    listen = [
      {
        addr = "0.0.0.0";
        port = 8448;
        ssl = true;
      }
      {
        addr = "[::]";
        port = 8448;
        ssl = true;
      }
    ];

    locations."/" = {
      proxyPass = matrixUpstream;
      proxyWebsockets = true;
      extraConfig = ''
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
      '';
    };
  };
  services.nginx.virtualHosts."rtc.imdomestic.com" = {
    serverName = "rtc.imdomestic.com";
    useACMEHost = "rtc.imdomestic.com";
    addSSL = true;
    http2 = true;
    listen = [
      {
        addr = "0.0.0.0";
        port = 8448;
        ssl = true;
      }
      {
        addr = "[::]";
        port = 8448;
        ssl = true;
      }
    ];

    locations."= /livekit/jwt" = {
      return = "308 /livekit/jwt/";
    };

    locations."/livekit/jwt/" = {
      proxyPass = "http://127.0.0.1:8088/";
      extraConfig = ''
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
      '';
    };

    locations."= /livekit/sfu" = {
      return = "308 /livekit/sfu/";
    };

    locations."/livekit/sfu/" = {
      proxyPass = "http://127.0.0.1:7880/";
      proxyWebsockets = true;
      extraConfig = ''
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
      '';
    };

    locations."/" = {
      return = "404";
    };
  };

  # Passwordless deploy from this box (it rebuilds itself, often driven
  # by an agent without a tty).  nixos-rebuild/nh only ever sudo three
  # things: `nix-env --set` on the system profile, the systemd-run
  # wrapper, and the generation's switch-to-configuration.  Deliberately
  # narrower than a blanket wheel NOPASSWD, though not a hard privilege
  # boundary — treat it as convenience, not containment.
  security.sudo.extraRules = lib.mkAfter [
    {
      users = ["hank"];
      commands = [
        {
          command = "/run/current-system/sw/bin/nix-env";
          options = ["NOPASSWD"];
        }
        {
          command = "/run/current-system/sw/bin/systemd-run";
          options = ["NOPASSWD"];
        }
        {
          command = "/nix/store/*/bin/switch-to-configuration";
          options = ["NOPASSWD"];
        }
      ];
    }
  ];

  system.stateVersion = "25.11";
}
