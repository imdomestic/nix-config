{
  inputs,
  pkgs,
  ...
}: {
  imports = [
    ../../modules/dae
    ./hardware-configuration.nix
  ];

  hardware.deviceTree = {
    enable = true;
    name = "rockchip/rk3328-nanopi-r2s.dtb";
    overlays = [
      {
        name = "r2s-1.5g-overclock";
        dtsText = ''
          /dts-v1/;
          /plugin/;

          / {
            compatible = "rockchip,rk3328";

            fragment@0 {
              target-path = "/opp-table-0";
              __overlay__ {
                opp-1512000000 {
                  opp-hz = /bits/ 64 <1512000000>;
                  opp-microvolt = <1450000>;
                  clock-latency-ns = <40000>;
                };
              };
            };
          };
        '';
      }
    ];
  };

  boot = {
    loader = {
      timeout = 1;
      grub.enable = false;
      generic-extlinux-compatible = {
        enable = true;
        configurationLimit = 15;
      };
    };
    kernelPackages = pkgs.linuxPackages_latest;
    kernelModules = [
      "tcp_bbr"
      "tcp_bbr"
      "nf_conntrack"
    ];
    kernelParams = [
      "console=ttyS2,1500000"
      "earlycon=uart8250,mmio32,0xff130000"
      "mitigations=off"
    ];
    blacklistedKernelModules = [
      "hantro_vpu"
      "drm"
      "lima"
      "rockchip_vdec"
    ];
    tmp.useTmpfs = true;
    growPartition = true;
    kernel.sysctl = {
      "net.core.default_qdisc" = "fq";
      "net.core.somaxconn" = 65536;
      "net.core.netdev_max_backlog" = 10000;
      "net.core.netdev_budget" = 600;
      "net.core.rps_sock_flow_entries" = 32768;
      "net.core.dev_weight" = 600;

      "net.ipv4.tcp_congestion_control" = "bbr";
      "net.ipv4.tcp_fastopen" = 3;
      "net.ipv4.tcp_keepalive_time" = 300;
      "net.ipv4.tcp_keepalive_intvl" = 30;
      "net.ipv4.tcp_keepalive_probes" = 5;
      "net.ipv4.tcp_mtu_probing" = true;
      "net.ipv4.tcp_notsent_lowat" = 16384;

      # tcp pending
      "net.ipv4.tcp_max_syn_backlog" = 65536;
      "net.ipv4.tcp_max_tw_buckets" = 2000000;
      "net.ipv4.tcp_tw_reuse" = true;
      "net.ipv4.tcp_fin_timeout" = 30;
      "net.ipv4.tcp_slow_start_after_idle" = false;

      # net mem
      "net.core.rmem_default" = 1048576;
      "net.core.rmem_max" = 16777216;
      "net.core.wmem_default" = 1048576;
      "net.core.wmem_max" = 16777216;
      "net.core.optmem_max" = 65536;
      "net.ipv4.tcp_rmem" = "4096 1048576 2097152";
      "net.ipv4.tcp_wmem" = "4096 65536 16777216";
      "net.ipv4.udp_rmem_min" = 8192;
      "net.ipv4.udp_wmem_min" = 8192;

      "net.ipv4.ip_forward" = true;
      "net.ipv4.conf.all.forwarding" = true;
      "net.ipv4.conf.default.forwarding" = true;
      "net.ipv6.conf.all.forwarding" = true;
      "net.ipv6.conf.default.forwarding" = true;
      "net.ipv4.conf.all.rp_filter" = 2;
      "net.ipv4.conf.default.rp_filter" = 2;

      "net.netfilter.nf_conntrack_buckets" = 393216;
      "net.netfilter.nf_conntrack_max" = 393216;
      "net.netfilter.nf_conntrack_generic_timeout" = 60;
      "net.netfilter.nf_conntrack_tcp_timeout_fin_wait" = 10;
      "net.netfilter.nf_conntrack_tcp_timeout_established" = 432000;
      "net.netfilter.nf_conntrack_tcp_timeout_time_wait" = 5;
    };
  };

  networking = {
    hostName = "r2s";
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
      tables.router = {
        name = "mss-clamping";
        enable = true;
        family = "inet";
        content = ''
          # Flowtable 定义
          flowtable f {
            hook ingress priority 0;
            devices = { end0, enu1, br-lan };
          }

          chain postrouting {
            type filter hook postrouting priority 0; policy accept;
            # 你的 MSS Clamping 规则
            oifname "ppp0" meta nfproto ipv4 tcp flags syn tcp option maxseg size set 1360
            oifname "ppp0" meta nfproto ipv6 tcp flags syn tcp option maxseg size set 1340
          }

          chain forward {
            type filter hook forward priority 0; policy accept;
            # flow offload @f
            ct state established,related accept
          }
        '';
      };
    };
  };

  systemd.network = {
    enable = true;
    netdevs."10-br-lan" = {
      netdevConfig = {
        Kind = "bridge";
        Name = "br-lan";
      };
    };

    # LAN2
    networks."20-lan2-uplink" = {
      matchConfig.Name = "enu1";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    # WAN, DHCP
    # networks."20-wan-uplink" = {
    #   matchConfig.Name = "end0";
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
      matchConfig.Name = "end0";
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
        Address = "192.168.4.1/24";
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
        DNS = ["192.168.4.1"];
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
    description = "Configure RPS/XPS/RFS for network interfaces";
    after = ["network-online.target"];
    wantedBy = ["multi-user.target"];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      shopt -s nullglob
      echo 32768 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true
      ${pkgs.ethtool} -G end0 rx 1024 tx 1024 2>/dev/null || true
      ${pkgs.ethtool} -G enu1 rx 1024 tx 1024 2>/dev/null || true

      # 8(0b1000, CPU3) for 24(xhci-hcd:usb4, extern0)
      echo 8 > /proc/irq/24/smp_affinity
      # 2(0b0010, CPU1) for 47(intern0)
      echo 2 > /proc/irq/47/smp_affinity

      for dev in end0 enu1; do
        [ -d /sys/class/net/$dev ] || continue

        for file in /sys/class/net/$dev/queues/rx-*/rps_cpus; do
          echo 7 > "$file" 2>/dev/null || true
        done

        for file in /sys/class/net/$dev/queues/rx-*/rps_flow_cnt; do
          echo 4096 > "$file" 2>/dev/null || true
        done

        for file in /sys/class/net/$dev/queues/tx-*/xps_cpus; do
          echo 7 > "$file" 2>/dev/null || true
        done
      done
    '';
  };

  services.pppd = {
    enable = true;
    peers = {
      mobile = {
        autostart = true;
        enable = true;
        config = ''
          plugin pppoe.so end0
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
      DNSStubListenerExtra=192.168.4.1
      DNSStubListenerExtra=::
    '';
  };
  services.irqbalance.enable = false;

  services.openssh.enable = true;
  services.openssh.settings = {
    PasswordAuthentication = true;
    KbdInteractiveAuthentication = true;
    PermitRootLogin = "yes";
  };
  services.tailscale = {
    enable = true;
  };

  time.timeZone = "Asia/Shanghai";
  i18n.defaultLocale = "en_US.UTF-8";

  environment.etc = {
    "systemd/journald.conf.d/99-storage.conf".text = ''
      [Journal]
      Storage=volatile
    '';
  };

  users.users.nixos = {
    isNormalUser = true;
    extraGroups = ["wheel"];
    initialPassword = "nixos";
  };

  users.users.hank = {
    isNormalUser = true;
    description = "hank";
    extraGroups = [
      "wheel"
    ];
  };

  powerManagement.cpuFreqGovernor = "performance";
  programs.zsh.enable = true;

  security.sudo.wheelNeedsPassword = false;
  nix.settings.trusted-users = [
    "root"
    "hank"
    "nixos"
    "@wheel"
  ];
  system.stateVersion = "25.11";
}
