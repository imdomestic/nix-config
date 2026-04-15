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

      # 纯交换机核心优化：禁止桥接流量被 netfilter (防火墙) 处理
      "net.bridge.bridge-nf-call-iptables" = 0;
      "net.bridge.bridge-nf-call-ip6tables" = 0;
      "net.bridge.bridge-nf-call-arptables" = 0;
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
    nftables = {
      enable = true;
      checkRuleset = true;
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

  systemd.services.enable-rps = {
    description = "Enable RPS for network interfaces";
    wantedBy = ["multi-user.target"];
    after = ["network.target"];
    script = ''
      for dev in enp1s0 enP1p17s0 wan0; do
        if [ -d "/sys/class/net/$dev/queues" ]; then
          for rx in /sys/class/net/$dev/queues/rx-*; do
            # f 对应二进制 1111，表示允许 CPU 0-3 处理
            echo f > "$rx/rps_cpus"
          done
        fi
      done
    '';
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
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
  services.openssh = {
    enable = true;
    ports = [22 2200];
  };

  services.nginx = {
    enable = true;
    clientMaxBodySize = "50m";
  };

  services.xray.enable = true;
  services.xray.settings = {
    log.loglevel = "warning";

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
        {
          tag = "bridge-r5s";
          domain = "reverse-r5s.hank.internal";
        }
        {
          tag = "bridge-r6s";
          domain = "reverse-r6s.hank.internal";
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
        tag = "interconn-r5s";
        protocol = "vless";
        settings = {
          vnext = [
            {
              address = "r5s.imdomestic.com";
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
        tag = "interconn-r6s";
        protocol = "vless";
        settings = {
          vnext = [
            {
              address = "r6s.imdomestic.com";
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
      {
        type = "field";
        inboundTag = ["bridge-r5s"];
        domain = ["full:reverse-r5s.hank.internal"];
        outboundTag = "interconn-r5s";
      }
      {
        type = "field";
        inboundTag = ["bridge-r6s"];
        domain = ["full:reverse-r6s.hank.internal"];
        outboundTag = "interconn-r6s";
      }

      # portal 转发来的“真实流量”（同样从 inboundTag=bridge 进入，但域名不是上面那个）=> 去 out
      {
        type = "field";
        inboundTag = ["bridge-h610" "bridge-rpi4" "bridge-sh" "bridge-r5s" "bridge-r6s"];
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
