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
    ];
    kernel.sysctl = {
      "net.ipv4.ip_forward" = 1;
      "net.ipv6.conf.all.forwarding" = 1;
      "net.core.default_qdisc" = "fq";
      "net.ipv4.tcp_congestion_control" = "bbr";
    };
  };

  time.timeZone = "Asia/Shanghai";

  powerManagement.cpuFreqGovernor = "schedutil";

  environment.systemPackages = with pkgs; [
    git
    python3
    mc
    psmisc
    curl
    wget
    dig
    file
    nvd
    ethtool
    sysstat
    neovim
    gcc
    nil
    btop
    neofetch
    ripgrep
    starship
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
        configFile = "${inputs.wg-config.outPath}/client_00007.conf";
        autostart = true;
      };
    };
    nftables = {
      enable = true;
      tables.mss-clamping = {
        name = "mss-clamping";
        enable = true;
        family = "inet";
        content = ''
          chain postrouting {
            type filter hook forward priority 0; policy accept;

            # IPv4：PPPoE MTU 1400 → MSS 1360
            oifname "ppp0" meta nfproto ipv4 tcp flags syn tcp option maxseg size set 1360

            # IPv6：PPPoE MTU 1400 → MSS 1340
            oifname "ppp0" meta nfproto ipv6 tcp flags syn tcp option maxseg size set 1340
          }
        '';
      };
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
      # 只需要链路层启动即可
      linkConfig.RequiredForOnline = "no";
      networkConfig = {
        # 必须禁用链路本地地址，防止干扰
        LinkLocalAddressing = "no";
        DHCP = "no";
        # 这里不需要 IPMasquerade 了，因为它是物理载体
      };
    };

    networks."25-wan-ppp" = {
      matchConfig.Name = "ppp0"; # 匹配 pppd 创建的接口
      networkConfig = {
        # 在这里开启 NAT (IPMasquerade)
        # IPMasquerade = "ipv4";

        # IPv6 配置 (PPPoE 也能获取 IPv6)
        IPv6AcceptRA = true;
        DHCP = "ipv6"; # 很多运营商通过 DHCPv6-PD 下发前缀
      };
      linkConfig = {
        RequiredForOnline = "carrier";
        MTUBytes = 1400;
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

  services.pppd = {
    enable = true;
    peers = {
      mobile = {
        autostart = true;
        enable = true;
        config = ''
          plugin pppoe.so wan0
          user "19551998351"
          password "837145"

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
          mtu 1400
          mru 1400
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
