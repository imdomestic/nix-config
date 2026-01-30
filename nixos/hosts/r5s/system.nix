{
  inputs,
  pkgs,
  ...
}: {
  imports = [
    ../../modules/dae
    ../../modules/keyd
  ];

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
      # "net.ipv6.conf.all.proxy_ndp" = 1; # dnp proxy
      # "net.ipv6.conf.wan0.proxy_ndp" = 1;

      "net.core.default_qdisc" = "fq";
      "net.ipv4.tcp_congestion_control" = "bbr";

      # 增加 backlog 防止丢包 (从脚本移到这里)
      # "net.core.netdev_max_backlog" = 16384;

      # 增加 TCP 缓冲区大小 (针对千兆/2.5G网络)
      # "net.core.rmem_max" = 16777216;
      # "net.core.wmem_max" = 16777216;
      # "net.ipv4.tcp_rmem" = "4096 87380 16777216";
      # "net.ipv4.tcp_wmem" = "4096 16384 16777216";

      # 增加连接跟踪表大小 (防止大量连接导致丢包)
      # "net.netfilter.nf_conntrack_max" = 65536;
      # "net.netfilter.nf_conntrack_tcp_timeout_established" = 7440;

      # ARP 缓存调整 (防止局域网设备多时 ARP 表溢出)
      # "net.ipv4.neigh.default.gc_thresh1" = 1024;
      # "net.ipv4.neigh.default.gc_thresh2" = 2048;
      # "net.ipv4.neigh.default.gc_thresh3" = 4096;
    };
  };

  time.timeZone = "Asia/Shanghai";

  powerManagement.cpuFreqGovernor = "performance";

  environment.systemPackages = with pkgs; [
    ndppd
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
    ];
  };

  i18n.defaultLocale = "en_GB.UTF-8";
  environment.etc = {
    "systemd/journald.conf.d/99-storage.conf".text = ''
      [Journal]
      Storage=volatile
    '';
  };

  networking = {
    hostName = "r5s";
    firewall.enable = false;
    networkmanager.enable = false;
    useNetworkd = true;
    wg-quick.interfaces = {
      wg0 = {
        configFile = "${inputs.wg-config.outPath}/client_00008.conf";
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
      #       oifname "wan0" meta nfproto ipv4 tcp flags syn tcp option maxseg size set 1360
      #       oifname "wan0" meta nfproto ipv6 tcp flags syn tcp option maxseg size set 1340
      #     }
      #
      #     chain forward {
      #       type filter hook forward priority 0; policy accept;
      #       # 开启硬件/软件卸载加速
      #       # flow offload @f
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

    # WAN, DHCP
    # networks."20-wan-uplink" = {
    #   matchConfig.Name = "wan0";
    #   networkConfig = {
    #     DHCP = "yes";
    #     IPv6AcceptRA = true;
    #   };
    #   linkConfig.RequiredForOnline = "carrier";
    #   dhcpV6Config = {
    #     PrefixDelegationHint = "::/60";
    #     UseDelegatedPrefix = true;
    #   };
    # };

    # WAN
    networks."20-wan-uplink" = {
      matchConfig.Name = "wan0";
      linkConfig.RequiredForOnline = "no";
      networkConfig = {
        LinkLocalAddressing = "no";
        DHCP = "no";
      };
    };

    networks."25-wan-ppp" = {
      matchConfig.Name = "ppp0"; # 匹配 pppd 创建的接口
      networkConfig = {
        # 在这里开启 NAT (IPMasquerade)
        # IPMasquerade = "ipv4";

        # IPv6 配置 (PPPoE 也能获取 IPv6)
        IPv6AcceptRA = true;
        # DHCP = "ipv6"; # 很多运营商通过 DHCPv6-PD 下发前缀
      };
      linkConfig = {
        RequiredForOnline = "carrier";
        # MTUBytes = 1400;
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
        Address = "192.168.3.1/24";
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
        DNS = ["192.168.3.1"];
      };

      # SLAAC
      ipv6SendRAConfig = {
        Managed = false; # no DHCPv6
        OtherInformation = false;
        EmitDNS = true; # send DNS with RA
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
      # f = 1111 (二进制) -> 允许所有4个核心处理中断
      for file in /sys/class/net/*/queues/rx-*/rps_cpus; do
        echo f > "$file"
      done
    '';
  };

  services.tailscale.enable = true;

  services.pppd = {
    enable = true;
    peers = {
      # 定义拨号连接名称，接口将是 ppp0
      telecom = {
        autostart = true;
        enable = true;
        config = ''
          plugin pppoe.so wan0
          user "051002554981"
          password "741852"

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
          # mtu 1400
          # mru 1400
        '';
      };
    };
  };

  services.dnsmasq.enable = false;
  services.resolved = {
    enable = true;
    fallbackDns = ["223.5.5.5"];
    extraConfig = ''
      DNSStubListener=yes
      DNSStubListenerExtra=192.168.3.1
      DNSStubListenerExtra=::
    '';
  };
  services.irqbalance.enable = true;
  services.openssh = {
    enable = true;
    ports = [22 2200];
  };

  programs.zsh.enable = true;

  nixpkgs.hostPlatform = "aarch64-linux";
  system.stateVersion = "25.11";
}
