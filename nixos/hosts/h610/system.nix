{
  pkgs,
  inputs,
  ...
}: {
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

    "net.ipv6.conf.all.accept_ra" = 2;
    "net.ipv6.conf.eno1.accept_ra" = 2;
    "net.ipv6.conf.default.accept_ra" = 2;
    "net.ipv6.conf.all.proxy_ndp" = 1;
    "net.ipv6.conf.eno1.proxy_ndp" = 1; # WAN口
    "net.ipv6.conf.br-lan.proxy_ndp" = 1; # LAN口

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
      # tables.mss-clamping = {
      #   name = "mss-clamping";
      #   enable = true;
      #   family = "inet";
      #   content = ''
      #     chain postrouting {
      #       type filter hook forward priority 0; policy accept;
      #
      #       # IPv4：PPPoE MTU 1400 → MSS 1360
      #       oifname "ppp0" meta nfproto ipv4 tcp flags syn tcp option maxseg size set 1360
      #
      #       # IPv6：PPPoE MTU 1400 → MSS 1340
      #       oifname "ppp0" meta nfproto ipv6 tcp flags syn tcp option maxseg size set 1340
      #     }
      #   '';
      # };
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

  services.ndppd = {
    enable = true;
    proxies = {
      "eno1" = {
        router = true;
        rules."::/0" = {
          interface = "br-lan";
        };
      };
      # "br-lan" = {
      #   router = true;
      #   rules."::/0" = {
      #     interface = "enp1s0u2";
      #   };
      # };
    };
  };

  systemd.services.ndppd = {
    after = ["network.target" "sys-subsystem-net-devices-br\\x2dlan.device"];
    bindsTo = ["sys-subsystem-net-devices-br\\x2dlan.device"];

    # 【保险2】无限重启策略
    serviceConfig = {
      Restart = "always";
      RestartSec = "5";
      ExecStartPre = "${pkgs.coreutils}/bin/sleep 2";
    };
  };

  services.radvd = {
    enable = true;
    config = ''
      interface br-lan {
        AdvSendAdvert on;
        MinRtrAdvInterval 3;
        MaxRtrAdvInterval 10;

        AdvDefaultLifetime 9000;

        AdvLinkMTU 1480;

        prefix ::/64 {
          AdvOnLink on;
          AdvAutonomous on;
          AdvRouterAddr on;

          Base6Interface eno1;
        };

        RDNSS 2400:3200::1 2400:3200:baba::1 {
        };
      };
    '';
  };

  services.networkd-dispatcher = {
    enable = true;
    rules = {
      "ipv6-relay-route" = {
        # 当接口状态变为 "routable" (已获取 IP 且可路由) 时触发
        onState = ["routable"];
        script = ''
          #!${pkgs.runtimeShell}

          # 定义接口名称
          WAN_IF="eno1"
          LAN_IF="br-lan"

          # 只有当触发事件的接口是 WAN 口时才执行
          if [ "$IFACE" != "$WAN_IF" ]; then
            exit 0
          fi

          echo "IPv6 Relay Script: Detecting prefix change on $WAN_IF..."

          # 提取 WAN 口的全球单播 IPv6 地址 (带掩码，例如 240e:xxx.../64)
          # 使用 ip -6 -o addr show ... 避免输出多行，awk 提取第4列 IP
          IP6_CIDR=$(${pkgs.iproute2}/bin/ip -6 -o addr show dev "$WAN_IF" scope global | ${pkgs.gawk}/bin/awk '{print $4}' | head -n 1)

          if [ -n "$IP6_CIDR" ]; then
             echo "IPv6 Relay Script: Found prefix $IP6_CIDR. Adding route to $LAN_IF."

             # 【核心魔法】
             # 添加一条路由：去往这个 /64 网段的包，扔给 LAN 口
             # metric 100 确保它的优先级高于内核自带的 WAN 口路由 (通常是 1024)
             # 使用 'replace' 而不是 'add'，防止脚本重复执行报错
             ${pkgs.iproute2}/bin/ip -6 route replace "$IP6_CIDR" dev "$LAN_IF" metric 100

             # 可选：重启 radvd 确保它尽快更新通告 (虽然 Base6Interface 通常会自动处理)
             # /run/current-system/sw/bin/systemctl try-reload-or-restart radvd
          else
             echo "IPv6 Relay Script: No global IPv6 address found on $WAN_IF."
          fi
        '';
      };
    };
  };

  # services.pppd = {
  #   enable = true;
  #   peers = {
  #     # 定义拨号连接名称，接口将是 ppp0
  #     chinamobile = {
  #       autostart = true;
  #       enable = true;
  #       config = ''
  #         plugin pppoe.so enp1s0u2
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

  # --- 3. Systemd-networkd 配置 (DHCP & RA) ---
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

    # WAN, DHCP
    networks."20-wan-uplink" = {
      matchConfig.Name = "eno1";
      networkConfig = {
        DHCP = "yes";
        IPv6AcceptRA = true;

        IPv6ProxyNDP = true;
      };
      linkConfig.RequiredForOnline = "routable";
      dhcpV6Config = {
        PrefixDelegationHint = "::/60";
        UseDelegatedPrefix = true;
      };
    };

    # networks."20-wan-uplink" = {
    #   matchConfig.Name = "enp1s0u2";
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
        Address = "192.168.22.1/24";
        DHCPServer = true;
        IPMasquerade = "ipv4";

        IPv6SendRA = false;
        IPv6AcceptRA = false;
        IPv6ProxyNDP = true; # 允许 NDP 穿透

        DHCPPrefixDelegation = true;
      };
      linkConfig = {
        # or "routable" with IP addresses configured
        RequiredForOnline = "no"; # carrier
      };

      dhcpServerConfig = {
        PoolOffset = 100;
        PoolSize = 100;
        EmitDNS = true;
        DNS = ["192.168.22.1"]; # 告诉客户端 DNS 找我 (然后被 dae 劫持)
      };

      # SLAAC
      # ipv6SendRAConfig = {
      #   Managed = false; # no DHCPv6
      #   OtherInformation = false;
      #   EmitDNS = true; # send DNS with RA
      #   UplinkInterface = "enp1s0u2";
      # };
    };
  };

  services.dnsmasq.enable = false;
  services.resolved = {
    enable = false;
    fallbackDns = ["223.5.5.5"];
    extraConfig = ''
      DNSStubListener=yes
      DNSStubListenerExtra=192.168.22.1
      DNSStubListenerExtra=::
    '';
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

  services.openssh.enable = true;

  system.stateVersion = "25.11";
}
