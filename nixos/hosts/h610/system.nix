{
  pkgs,
  inputs,
  config,
  lib,
  ...
}: {
  imports = [
    ../../modules/dae
    ../../modules/keyd
    # ../../modules/netbird
    # ../../modules/minecraft/wuxi.nix
  ];

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.kernelParams = [
    "pcie_aspm=off"
    "i915.force_probe=!56a5"
    "xe.force_probe=56a5"
    "enable_guc=3"
  ];
  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
    "net.core.default_qdisc" = "fq";
    "net.ipv4.tcp_congestion_control" = "bbr";
  };

  time.timeZone = "Hongkong";

  networking = {
    hostName = "h610"; # Define your hostname.
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
    wg-quick.interfaces = {
      wg0 = {
        configFile = "${inputs.wg-config.outPath}/client_00004.conf";
        autostart = true;
      };
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

  services.dnsmasq.enable = false;
  services.resolved = {
    enable = true;
    fallbackDns = ["223.5.5.5"];
    extraConfig = ''
      DNSStubListener=yes
      DNSStubListenerExtra=10.0.1.1
      DNSStubListenerExtra=::
    '';
  };

  users.groups.nginx = {};

  security.acme = {
    acceptTerms = true;
    defaults.email = "hankchogan@gmail.com";
  };

  security.acme.certs."tailscale.imdomestic.com" = {
    dnsProvider = "cloudflare";
    credentialsFile = "/var/lib/secrets/acme/cloudflare.env";
    group = "nginx";
  };

  systemd.services.ddns-go = let
    ddnsConfig = pkgs.writeText "ddns-go-config.yaml" ''
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
            ipv6:
              enable: false
              gettype: netInterface
              url: https://speed.neu6.edu.cn/getIP.php, https://v6.ident.me, https://6.ipw.cn, https://v6.yinghualuo.cn/bejson
              netinterface: br-lan
              cmd: ""
              ipv6reg: ""
              domains:
                  - ""
            dns:
              name: cloudflare
              id: ""
              secret: WY4F4gK8O-VgV1P7dGnic4yNSxmtPBep5OXuh2Js
            ttl: ""
          - name: "root"
            ipv4:
              enable: true
              gettype: netInterface
              url: https://myip.ipip.net, https://ddns.oray.com/checkip, https://ip.3322.net, https://4.ipw.cn, https://v4.yinghualuo.cn/bejson
              netinterface: ppp0
              cmd: ""
              domains:
                  - imdomestic.com
            ipv6:
              enable: false
              gettype: netInterface
              url: https://speed.neu6.edu.cn/getIP.php, https://v6.ident.me, https://6.ipw.cn, https://v6.yinghualuo.cn/bejson
              netinterface: br-lan
              cmd: ""
              ipv6reg: ""
              domains:
                  - ""
            dns:
              name: cloudflare
              id: ""
              secret: WY4F4gK8O-VgV1P7dGnic4yNSxmtPBep5OXuh2Js
            ttl: ""
      user:
          username: hank
          password: $2a$10$t8pMXiYscv9Zi4SEUjw9S.1H0XeGbDrSxcC8O0hvjDphPd./2Anh.
      webhook:
          webhookurl: ""
          webhookrequestbody: ""
          webhookheaders: ""
      notallowwanaccess: false
      lang: zh
    '';
  in {
    enable = true;
    description = "ddns-go";

    wantedBy = ["multi-user.target"];
    wants = ["network-online.target"];
    after = ["network-online.target"];

    serviceConfig = {
      ExecStart = "${pkgs.ddns-go.outPath}/bin/ddns-go -f 300 -c ${ddnsConfig}";
      Restart = "always";
      RestartSec = 5;
    };
  };

  services.xray.enable = true;
  services.xray.settings = {
    log.loglevel = "debug";

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
            dest = "www.microsoft.com:443";
            serverNames = ["www.microsoft.com" "microsoft.com"];
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
            dest = "www.microsoft.com:443";
            serverNames = ["www.microsoft.com" "microsoft.com"];
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

  services.xserver.displayManager.gdm.enable = false;
  services.xserver.desktopManager.gnome.enable = false;

  services.cockpit.enable = lib.mkForce false;

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
    ];
    enable32Bit = true;
  };

  environment = {
    variables = {
      EDITOR = "nvim";
    };
  };

  environment.systemPackages = with pkgs; [
    gcc
    neovim
    nginx
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
      server_url = "https://tailscale.imdomestic.com:8443";
      derp.server = {
        enable = true;
        region_id = 610;
        region_code = "h610";
        region_name = "H610";
        stun_listen_addr = "0.0.0.0:3478";
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

  services.headplane = {
    enable = true;
    settings = {
      server = {
        host = "127.0.0.1";
        port = 3000;
        base_url = "https://tailscale.imdomestic.com:8443";
        cookie_secure = true;
        cookie_secret_path = "/var/lib/secrets/headplane/cookie_secret";
      };
      headscale = {
        url = "https://tailscale.imdomestic.com:8443";
      };
      integration = {
        agent.enabled = false;
        proc.enabled = true;
      };
    };
  };

  services.nginx.enable = true;
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

    locations."/admin" = {
      proxyPass = "http://127.0.0.1:3000";
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
  };

  system.stateVersion = "25.11";
}
