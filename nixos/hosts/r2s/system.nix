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
      "net.ipv4.ip_forward" = 1;
      "net.core.default_qdisc" = "fq";
      "net.ipv4.tcp_congestion_control" = "bbr";
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
    wants = ["network-online.target"];
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
          mtu 1492
          mru 1492
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

  systemd.services.ddns-go = let
    ddnsConfig = pkgs.writeText "ddns-go-config.yaml" ''
      dnsconf:
          - name: ""
            ipv4:
              enable: false
              gettype: url
              url: https://myip.ipip.net, https://ddns.oray.com/checkip, https://ip.3322.net, https://4.ipw.cn, https://v4.yinghualuo.cn/bejson
              netinterface: wan0
              cmd: ""
              domains:
                  - ""
            ipv6:
              enable: true
              gettype: netInterface
              url: https://speed.neu6.edu.cn/getIP.php, https://v6.ident.me, https://6.ipw.cn, https://v6.yinghualuo.cn/bejson
              netinterface: ppp0
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
