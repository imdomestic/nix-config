{
  inputs,
  pkgs,
  ...
}: let
  ddnsConfig = pkgs.writeText "ddns-go-config.yaml" ''
    dnsconf:
        - name: ""
          ipv4:
            enable: false
            gettype: url
            url: https://myip.ipip.net, https://ddns.oray.com/checkip, https://ip.3322.net, https://4.ipw.cn, https://v4.yinghualuo.cn/bejson
            netinterface: br-lan
            cmd: ""
            domains:
                - ""
          ipv6:
            enable: true
            gettype: netInterface
            url: https://speed.neu6.edu.cn/getIP.php, https://v6.ident.me, https://6.ipw.cn, https://v6.yinghualuo.cn/bejson
            netinterface: br-lan
            cmd: ""
            ipv6reg: ""
            domains:
                - r5sjp:imdomestic.com
                - matrix:imdomestic.com
          dns:
            name: cloudflare
            id: ""
            secret: WY4F4gK8O-VgV1P7dGnic4yNSxmtPBep5OXuh2Js
          ttl: ""
    user:
        username: hank
        password: $2a$10$Jk0oGrcwc5NyTXyeDJebxeET1efrILq64Y9.8112NLW2qMmizFSIK
    webhook:
        webhookurl: ""
        webhookrequestbody: ""
        webhookheaders: ""
    notallowwanaccess: false
    lang: zh
  '';
in {
  imports = [
    ../../modules/keyd
  ];

  security.acme = {
    acceptTerms = true;
    defaults.email = "hankchogan@gmail.com";
  };

  security.acme.certs."matrix.imdomestic.com" = {
    dnsProvider = "cloudflare";
    credentialsFile = "/var/lib/secrets/acme/cloudflare.env";
    group = "nginx";
  };

  fileSystems = {
    "/" = {
      device = "/dev/disk/by-label/NIXOS";
      fsType = "ext4";
    };
    "/var/log" = {
      fsType = "tmpfs";
    };
  };

  hardware.firmware = [
    pkgs.linux-firmware
  ];
  hardware.deviceTree.name = "rockchip/rk3568-nanopi-r5s.dtb";

  boot = {
    loader = {
      grub.enable = false;
      generic-extlinux-compatible = {
        enable = true;
        useGenerationDeviceTree = true;
      };
      timeout = 1;
    };
    tmp.useTmpfs = true;
    growPartition = true;
    kernelPackages = pkgs.linuxPackages_latest;
    initrd.availableKernelModules = [
      "sdhci_of_dwcmshc"
      "dw_mmc_rockchip"
      "analogix_dp"
      "io-domain"
      "rockchip_saradc"
      "rockchip_thermal"
      "rockchipdrm"
      "rockchip-rga"
      "pcie_rockchip_host"
      "phy-rockchip-pcie"
      "phy_rockchip_snps_pcie3"
      "phy_rockchip_naneng_combphy"
      "phy_rockchip_inno_usb2"
      "dwmac_rk"
      "dw_wdt"
      "dw_hdmi"
      "dw_hdmi_cec"
      "dw_hdmi_i2s_audio"
      "dw_mipi_dsi"
    ];
    kernelParams = [
      "console=tty0"
      "earlycon=uart8250,mmio32,0xfe660000"
      "pcie_aspm=off" # 关闭 PCIe 节能
    ];
    kernel.sysctl = {
      "net.ipv4.ip_forward" = 1;
      "net.ipv6.conf.all.forwarding" = 1;
      "net.core.default_qdisc" = "fq";
      "net.ipv4.tcp_congestion_control" = "bbr";

      # 增加 backlog 防止丢包 (从脚本移到这里)
      "net.core.netdev_max_backlog" = 16384;

      # 增加 TCP 缓冲区大小 (针对千兆/2.5G网络)
      "net.core.rmem_max" = 16777216;
      "net.core.wmem_max" = 16777216;
      "net.ipv4.tcp_rmem" = "4096 87380 16777216";
      "net.ipv4.tcp_wmem" = "4096 16384 16777216";

      # 增加连接跟踪表大小 (防止大量连接导致丢包)
      "net.netfilter.nf_conntrack_max" = 65536;
      "net.netfilter.nf_conntrack_tcp_timeout_established" = 7440;

      # ARP 缓存调整 (防止局域网设备多时 ARP 表溢出)
      "net.ipv4.neigh.default.gc_thresh1" = 1024;
      "net.ipv4.neigh.default.gc_thresh2" = 2048;
      "net.ipv4.neigh.default.gc_thresh3" = 4096;
    };
  };

  time.timeZone = "Asia/Shanghai";
  services.displayManager.gdm.enable = false;
  services.desktopManager.gnome.enable = false;

  powerManagement.cpuFreqGovernor = "performance";

  environment.systemPackages = with pkgs; [
    vim
    tcpdump
    iproute2
    ethtool
    mtr
    tailscale
  ];

  security.sudo.wheelNeedsPassword = false;
  nix.settings.trusted-users = [
    "root"
    "@wheel"
  ];

  users.users.nix = {
    isNormalUser = true;
    description = "nix";
    extraGroups = [
      "wheel"
    ];
    password = "nix";
  };

  users.users.hank = {
    isNormalUser = true;
    description = "hank";
    extraGroups = [
      "wheel"
      "podman"
    ];
  };

  virtualisation = {
    containers.enable = true;
    podman = {
      enable = true;
      dockerCompat = true;
      defaultNetwork.settings.dns_enabled = true; # Required for containers under podman-compose to be able to talk to each other.
    };
  };

  i18n.defaultLocale = "en_GB.UTF-8";
  environment.etc = {
    "systemd/journald.conf.d/99-storage.conf".text = ''
      [Journal]
      Storage=volatile
    '';
  };

  networking = {
    hostName = "r5sjp";
    firewall.enable = false;
    networkmanager.enable = false;
    useNetworkd = true;
    wg-quick.interfaces = {
      wg0 = {
        configFile = "${inputs.wg-config.outPath}/client_00007.conf";
        autostart = true;
      };
    };
    nftables = {
      enable = true;
      checkRuleset = false;
      # tables.router = {
      #   name = "mss-clamping";
      #   enable = true;
      #   family = "inet";
      #   content = ''
      #     # Flowtable 定义
      #     flowtable f {
      #       hook ingress priority 0;
      #       devices = { wan0, br-lan };
      #     }
      #
      #     chain postrouting {
      #       type filter hook postrouting priority 0; policy accept;
      #       # 你的 MSS Clamping 规则
      #       oifname "ppp0" meta nfproto ipv4 tcp flags syn tcp option maxseg size set 1360
      #       oifname "ppp0" meta nfproto ipv6 tcp flags syn tcp option maxseg size set 1340
      #     }
      #
      #     chain forward {
      #       type filter hook forward priority 0; policy accept;
      #       # 开启硬件/软件卸载加速
      #       flow offload @f
      #       ct state established,related accept
      #     }
      #   '';
      # };
    };
  };
  systemd.network = {
    enable = true;
    links = {
      "10-wan0" = {
        matchConfig = {
          Path = "platform-fe2a0000.ethernet";
        };
        linkConfig = {
          Name = "wan0";
        };
      };
    };

    netdevs."10-br-lan" = {
      netdevConfig = {
        Kind = "bridge";
        Name = "br-lan";
      };
    };

    # LAN1
    networks."20-lan1-uplink" = {
      matchConfig.Name = "enp1s0";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    # LAN2
    networks."20-lan2-uplink" = {
      matchConfig.Name = "enP1p17s0";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    # WAN
    networks."20-wan-uplink" = {
      matchConfig.Name = "wan0";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    # WAN
    # networks."20-wan-uplink" = {
    #   matchConfig.Name = "wan0";
    #   # 只需要链路层启动即可
    #   linkConfig.RequiredForOnline = "no";
    #   networkConfig = {
    #     # 必须禁用链路本地地址，防止干扰
    #     LinkLocalAddressing = "no";
    #     DHCP = "no";
    #     # 这里不需要 IPMasquerade 了，因为它是物理载体
    #   };
    # };

    # networks."25-wan-ppp" = {
    #   matchConfig.Name = "ppp0"; # 匹配 pppd 创建的接口
    #   networkConfig = {
    #     # 在这里开启 NAT (IPMasquerade)
    #     # IPMasquerade = "ipv4";
    #
    #     # IPv6 配置 (PPPoE 也能获取 IPv6)
    #     IPv6AcceptRA = true;
    #     DHCP = "ipv6"; # 很多运营商通过 DHCPv6-PD 下发前缀
    #   };
    #   linkConfig = {
    #     RequiredForOnline = "carrier";
    #     MTUBytes = 1400;
    #   };
    #   dhcpV6Config = {
    #     WithoutRA = "solicit";
    #     PrefixDelegationHint = "::/60";
    #     UseDelegatedPrefix = true;
    #   };
    # };

    networks."30-br-lan" = {
      matchConfig.Name = "br-lan";
      networkConfig = {
        DHCP = "yes";
        IPv6AcceptRA = true;
      };
      linkConfig = {
        RequiredForOnline = "routable";
      };
    };
  };

  systemd.services.network-rps = {
    description = "Configure RPS for network interfaces";
    after = ["network.target"];
    wantedBy = ["multi-user.target"];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      for file in /sys/class/net/*/queues/rx-*/rps_cpus; do
        echo f > "$file"
      done
    '';
  };

  # services.pppd = {
  #   enable = true;
  #   peers = {
  #     mobile = {
  #       autostart = true;
  #       enable = true;
  #       config = ''
  #         plugin pppoe.so wan0
  #         user "19551998351"
  #         password "837145"
  #
  #         # usepeerdns
  #
  #         # 关键参数
  #         defaultroute    # 自动添加默认路由
  #         persist         # 断线重连
  #         maxfail 0       # 无限次重试
  #         holdoff 5       # 重试间隔
  #         noipdefault
  #         noauth
  #         hide-password
  #         lcp-echo-interval 30
  #         lcp-echo-failure 20
  #         lcp-echo-adaptive
  #
  #         +ipv6
  #         ipv6cp-use-ipaddr
  #
  #         # MTU 设置 (PPPoE 标准)
  #         mtu 1400
  #         mru 1400
  #       '';
  #     };
  #   };
  # };

  services.dnsmasq.enable = false;
  services.resolved = {
    enable = true;
    fallbackDns = ["223.5.5.5"];
    extraConfig = ''
      DNSStubListener=yes
      DNSStubListenerExtra=::
    '';
  };
  services.irqbalance.enable = true;
  services.openssh = {
    enable = true;
    ports = [22 2200];
  };

  services.nginx = {
    enable = true;
    clientMaxBodySize = "50m";
  };
  services.nginx.virtualHosts."matrix.imdomestic.com" = {
    serverName = "matrix.imdomestic.com";
    useACMEHost = "matrix.imdomestic.com";
    forceSSL = true;
    http2 = true;

    locations."=/.well-known/matrix/client" = {
      extraConfig = ''
        add_header Content-Type application/json;
        add_header Access-Control-Allow-Origin *;
        return 200 '{"m.homeserver": {"base_url": "https://matrix.imdomestic.com"}, "org.matrix.msc3575.proxy": {"url": "https://matrix.imdomestic.com"}}';
      '';
    };

    locations."=/.well-known/matrix/server" = {
      extraConfig = ''
        add_header Content-Type application/json;
        add_header Access-Control-Allow-Origin *;
        return 200 '{"m.server": "matrix.imdomestic.com:443"}';
      '';
    };

    locations."/" = {
      root = pkgs.element-web.override {
        conf = {
          default_server_config = {
            "m.homeserver" = {
              "base_url" = "https://matrix.imdomestic.com";
              "server_name" = "matrix.imdomestic.com";
            };
          };
          default_theme = "dark";
          show_labs_settings = true;
        };
      };
      index = "index.html";
      extraConfig = ''
        try_files $uri $uri/ /index.html;
      '';
    };

    locations."~ ^/(_matrix|_synapse|/.well-known)" = {
      proxyPass = "http://10.0.0.66:8008";
      proxyWebsockets = true;
      extraConfig = ''
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
      '';
    };
  };

  services.xray.enable = true;
  services.xray.settings = {
    log.loglevel = "debug";

    reverse = {
      bridges = [
        {
          tag = "bridge-h610";
          domain = "reverse-h610.hank.internal";
        }
        {
          tag = "bridge-rpi4";
          domain = "reverse-rpi4.hank.internal";
        }
        {
          tag = "bridge-sh";
          domain = "reverse-sh.hank.internal";
        }
      ];
    };

    outbounds = [
      {
        tag = "interconn-h610";
        protocol = "vless";
        settings = {
          vnext = [
            {
              address = "h610.imdomestic.com";
              port = 1443;
              users = [
                {
                  id = "2cac4128-2151-4a28-8102-ea1806f9c12b";
                  flow = "xtls-rprx-vision";
                  encryption = "none";
                }
              ];
            }
          ];
        };
        streamSettings = {
          network = "tcp";
          security = "reality";
          realitySettings = {
            serverName = "www.microsoft.com";
            publicKey = "2oMfAnRmOiZN3ra85D05Zhr8ehI8hRSRqzpJ0oJUcgM";
            fingerprint = "chrome";
            shortId = "16";
          };
        };
      }

      {
        tag = "interconn-rpi4";
        protocol = "vless";
        settings = {
          vnext = [
            {
              address = "rpi4.imdomestic.com";
              port = 2443;
              users = [
                {
                  id = "4417cfd8-49e5-4ca3-bcc7-4e80f5f1bb40";
                  flow = "xtls-rprx-vision";
                  encryption = "none";
                }
              ];
            }
          ];
        };
        streamSettings = {
          network = "tcp";
          security = "reality";
          realitySettings = {
            serverName = "www.microsoft.com";
            publicKey = "pfPKRWuFm6pJ6Lb7y6n5HW_YTNArhbtliYbQ3kSjkXo";
            fingerprint = "chrome";
            shortId = "17";
          };
        };
      }

      {
        tag = "interconn-sh";
        protocol = "vless";
        settings = {
          vnext = [
            {
              address = "sh.imdomestic.com";
              port = 3443;
              users = [
                {
                  id = "2cac4128-2151-4a28-8102-ea1806f9c12b";
                  flow = "xtls-rprx-vision";
                  encryption = "none";
                }
              ];
            }
          ];
        };
        streamSettings = {
          network = "tcp";
          security = "reality";
          realitySettings = {
            serverName = "www.microsoft.com";
            publicKey = "GWoWYGsFBtkpzl_PqTSPrU2sfBlT36RNZMPSW20liww";
            fingerprint = "chrome";
            shortId = "16";
          };
        };
      }

      {
        tag = "out";
        protocol = "freedom";
      }
      # 如果你想转发到本机 Web 服务：把上面 out 改成
      # { tag="out"; protocol="freedom"; settings.redirect="127.0.0.1:80"; }
    ];

    routing.rules = [
      {
        type = "field";
        inboundTag = ["bridge-h610"];
        domain = ["full:reverse-h610.hank.internal"];
        outboundTag = "interconn-h610";
      }
      {
        type = "field";
        inboundTag = ["bridge-rpi4"];
        domain = ["full:reverse-rpi4.hank.internal"];
        outboundTag = "interconn-rpi4";
      }
      {
        type = "field";
        inboundTag = ["bridge-sh"];
        domain = ["full:reverse-sh.hank.internal"];
        outboundTag = "interconn-sh";
      }

      # portal 转发来的“真实流量”（同样从 inboundTag=bridge 进入，但域名不是上面那个）=> 去 out
      {
        type = "field";
        inboundTag = ["bridge-h610" "bridge-rpi4" "bridge-sh"];
        outboundTag = "out";
      }
    ];
  };

  systemd.services.ddns-go = {
    enable = true;
    description = "ddns";

    wantedBy = ["multi-user.target"];
    wants = ["network-online.target"];
    after = ["network-online.target"];

    serviceConfig = {
      ExecStart = "${pkgs.ddns-go.outPath}/bin/ddns-go -f 300 -c ${ddnsConfig}";
      Restart = "always";
      RestartSec = 5;
    };
  };

  services.tailscale.enable = true;

  programs.zsh.enable = true;

  nixpkgs.hostPlatform = "aarch64-linux";
  system.stateVersion = "25.11";
}
