{
  pkgs,
  inputs,
  config,
  lib,
  ...
}: let
  domain = "h610.imdomestic.com";
  zitadelPort = 8443; # 外部访问 Zitadel 的端口
  netbirdPort = 9443; # 外部访问 NetBird 的端口
  oidcClientId = "NETBIRD_CLIENT_ID_FROM_ZITADEL";
  oidcClientSecret = "NETBIRD_CLIENT_SECRET_FROM_ZITADEL";
  cloudflareTokenFile = "/etc/nixos/cloudflare-token";
  caddyWithCloudflare = pkgs.caddy.withPlugins {
    plugins = ["github.com/caddy-dns/cloudflare@v0.2.3"];
    hash = "sha256-bJO2RIa6hYsoVl3y2L86EM34Dfkm2tlcEsXn2+COgzo=";
  };
  ddnsConfig = pkgs.writeText "ddns-go-config.yaml" ''
    dnsconf:
        - name: ""
          ipv4:
            enable: true
            gettype: netInterface
            url: https://myip.ipip.net, https://ddns.oray.com/checkip, https://ip.3322.net, https://4.ipw.cn, https://v4.yinghualuo.cn/bejson
            netinterface: ppp0
            cmd: ""
            domains:
                - h610:imdomestic.com
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
            secret: REMOVED_SECRET_CLOUDFLARE_API_TOKEN_1e6e67ea94941305
          ttl: ""
    user:
        username: hank
        password: REMOVED_SECRET_DDNS_BCRYPT_PASSWORD_HASH_f41c83e46c6a3217
    webhook:
        webhookurl: ""
        webhookrequestbody: ""
        webhookheaders: ""
    notallowwanaccess: false
    lang: zh
  '';
in {
  imports = [
    ../../modules/dae
    ../../modules/keyd
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
      checkRuleset = false;
      tables.router = {
        name = "mss-clamping";
        enable = true;
        family = "inet";
        content = ''
          flowtable f {
            hook ingress priority 0;
            devices = { eno1, br-lan };
          }

          chain postrouting {
            type filter hook postrouting priority 0; policy accept;

            oifname "ppp0" meta nfproto ipv4 tcp flags syn tcp option maxseg size set 1452
            oifname "ppp0" meta nfproto ipv6 tcp flags syn tcp option maxseg size set 1432
          }

          chain forward {
            type filter hook forward priority 0; policy accept;
            # flow offload @f
            ct state established,related accept
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

          # MTU 设置 (PPPoE 标准)
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
        Address = "192.168.2.1/24";
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
        DNS = ["192.168.2.1"];
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
      DNSStubListenerExtra=192.168.2.1
      DNSStubListenerExtra=::
    '';
  };

  systemd.services.ddns-go = {
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
              id = "REMOVED_SECRET_VLESS_CLIENT_UUID_63a5353352a6c3d3";
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
            privateKey = "REMOVED_SECRET_REALITY_PRIVATE_KEY_9c213acc25f34bcd";
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
              id = "REMOVED_SECRET_VLESS_CLIENT_UUID_63a5353352a6c3d3";
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
            privateKey = "REMOVED_SECRET_REALITY_PRIVATE_KEY_9c213acc25f34bcd";
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

  services.cockroachdb = {
    enable = true;
    insecure = true; # 本地单节点运行，不强制 SSL，方便 Zitadel 连接
    listen.address = "127.0.0.1"; # 只监听本地，不要暴露给公网
    http.address = "127.0.0.1";
  };
  systemd.services.caddy.serviceConfig = {
    EnvironmentFile = "/etc/caddy/cloudflare.env";
  };
  services.caddy = {
    enable = true;
    package = caddyWithCloudflare;

    # Caddy 全局配置：配置 DNS-01 验证
    globalConfig = ''
      acme_dns cloudflare {env.CLOUDFLARE_API_TOKEN}
    '';

    virtualHosts = {
      # Zitadel 入口
      "https://${domain}:${toString zitadelPort}" = {
        extraConfig = ''
          reverse_proxy h2c://localhost:8080
        '';
      };

      # NetBird 入口 (Dashboard + API + Signal 复用端口)
      "https://${domain}:${toString netbirdPort}" = {
        extraConfig = ''
          # 1. 静态 Dashboard 文件
          root * ${config.services.netbird.server.dashboard.finalDrv}
          file_server

          # 2. Management API (HTTP)
          handle /api* {
            reverse_proxy localhost:8011
          }

          # 3. Management API (gRPC)
          handle /management.ManagementService/* {
            reverse_proxy h2c://localhost:8011
          }

          # 4. Signal (gRPC)
          handle /signalexchange.SignalExchange/* {
            reverse_proxy h2c://localhost:8012
          }

          # 5. 处理前端路由 (SPA)
          try_files {path} {path}/ /index.html
        '';
      };
    };
  };

  services.zitadel = {
    enable = true;
    masterKeyFile = "/etc/nixos/zitadel-masterkey"; # 步骤二生成的文件
    settings = {
      Port = 8080;
      ExternalSecure = true;
      ExternalDomain = "${domain}:${toString zitadelPort}";
      ExternalPort = zitadelPort;
      # 禁用自带 TLS，由 Caddy 处理
      TLS = {
        Enabled = false;
      };
    };
  };

  services.netbird.server = {
    enable = true;
    domain = "${domain}:${toString netbirdPort}"; # 这里的 Domain 必须带端口
    enableNginx = false; # 我们使用 Caddy，禁用内置 Nginx

    # 管理服务
    management = {
      port = 8011;
      metricsPort = 9090;
      dnsDomain = "netbird.local"; # 内网 peer 域名后缀

      # OIDC 配置：指向 Zitadel
      oidcConfigEndpoint = "https://${domain}:${toString zitadelPort}/.well-known/openid-configuration";

      settings = {
        # 认证流程配置
        HttpConfig = {
          # 必须显式设置，否则可能获取不到带端口的 URL
          OIDCConfigEndpoint = "https://${domain}:${toString zitadelPort}/.well-known/openid-configuration";
          AuthAudience = oidcClientId;
        };

        # 这里的 ClientID 需要在 Zitadel 中创建后填入
        PKCEAuthorizationFlow = {
          ProviderConfig = {
            ClientID = oidcClientId;
            Audience = oidcClientId;
            RedirectURLs = ["http://localhost:53000"]; # 本地 CLI 登录回调
          };
        };
        DeviceAuthorizationFlow = {
          Provider = "hosted";
          ProviderConfig = {
            ClientID = oidcClientId;
            Audience = oidcClientId;
          };
        };
      };
    };

    # 信令服务
    signal = {
      port = 8012;
    };

    # Dashboard 配置
    dashboard = {
      # Dashboard 配置会被编译进前端静态文件
      settings = {
        AUTH_AUTHORITY = "https://${domain}:${toString zitadelPort}";
        AUTH_CLIENT_ID = oidcClientId;
        AUTH_AUDIENCE = oidcClientId;
        AUTH_SUPPORTED_SCOPES = "openid profile email offline_access";
        USE_AUTH0 = false;
        NETBIRD_TOKEN_SOURCE = "accessToken"; # Zitadel 通常用 accessToken
      };
    };

    # Coturn 中继服务器
    coturn = {
      enable = true;
      password = "YOUR_COTURN_SECRET"; # 建议使用 passwordFile 并在生产环境中保密
    };
  };

  # --- 4. NetBird Client (本机加入网络) ---
  services.netbird.clients.default = {
    port = 51820;
    interface = "wt0";
    # 自动连接到我们自建的服务器
    # 注意：客户端初次连接通常需要 `netbird up --management-url ...`
    # NixOS 模块可能只负责启动 daemon。
    # 建议在系统启动后手动执行一次登录命令。
  };

  services.xserver.displayManager.gdm.enable = false;
  services.xserver.desktopManager.gnome.enable = false;

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

  environment.sessionVariables = {
    LIBVA_DRIVER_NAME = "iHD";
    NIXOS_OZONE_WL = "1";
  };
  xdg.portal.config.common.default = "*";

  services.openssh.enable = true;
  services.tailscale.enable = true;

  system.stateVersion = "25.11";
}
