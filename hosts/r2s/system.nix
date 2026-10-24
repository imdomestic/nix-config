{
  config,
  pkgs,
  ...
}: let
  wg = import ../../lib/wgClient.nix {inherit pkgs;} {
    privateKeyFile = config.sops.secrets."wireguard/private_key".path;
    presharedKeyFile = config.sops.secrets."wireguard/preshared_key".path;
    address = "10.0.0.9/24";
  };
in {
  imports = [
    ../../system/modules/dae
    # ../../system/modules/singbox
    ./hardware-configuration.nix
    ../../system/modules/vlmcsd
  ];

  sops.secrets."wireguard/private_key".owner = "systemd-network";
  sops.secrets."wireguard/preshared_key".owner = "systemd-network";

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
    firewall = {
      enable = true;
      # LAN 整段信任:dae 透明代理把局域网设备访问任意端口的连接送进本机 INPUT,
      # 目标端口保持原样,没法按端口列。公网流量走 ppp0,不受影响。
      trustedInterfaces = ["br-lan"];
      # 策略路由加透明代理,rpfilter 会误杀。
      checkReversePath = false;
      # xray portal 的两个入站。
      allowedTCPPorts = [2444 54322];
      # DHCPv6-PD 的回包。
      interfaces.ppp0.allowedUDPPorts = [546];
    };
    networkmanager.enable = false;
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
  };

  systemd.network = {
    enable = true;
    netdevs."10-br-lan" = {
      netdevConfig = {
        Kind = "bridge";
        Name = "br-lan";
      };
    };
    netdevs."40-wg0" = wg.netdev;
    networks."40-wg0" = wg.network;

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
      linkConfig = {
        RequiredForOnline = "no";
        # MTUBytes = 9000;
      };
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
        # pppd 通过 IPCP 装上 IPv4;networkd 重启时保留它,
        # 否则 `nixos-rebuild switch` 会把 ppp0 的 IPv4 冲掉。
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
          # user "19551998351"
          # password "837145"
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
          mtu 1492
          mru 1492
        '';
      };
    };
  };

  services.dnsmasq.enable = false;
  services.resolved = {
    enable = true;
    settings.Resolve = {
      FallbackDNS = ["223.5.5.5"];
      DNSSEC = "false";
      DNSStubListener = "yes";
      DNSStubListenerExtra = ["192.168.4.1" "::"];
    };
  };
  services.irqbalance.enable = false;

  services.openssh.enable = true;
  my.ddns.enable = true;

  # Xray 的凭据全部走 sops。整份配置由 sops.templates 在 /run 下渲染，
  # 避免 UUID 和 Reality 私钥进入公开仓库或 world-readable 的 nix store。
  sops.secrets."xray/reality_private_key" = {};
  sops.secrets."xray/interconn2_uuid" = {};
  sops.secrets."xray/interconn2_short_id" = {};
  sops.secrets."xray/client_in2_uuid" = {};
  sops.secrets."xray/client_in2_short_id" = {};
  services.xray.enable = true;
  services.xray.settingsFile = config.sops.templates."xray-config.json".path;

  sops.templates."xray-config.json" = {
    restartUnits = ["xray.service"];
    content = let
      s = config.sops.placeholder;

      aliyun = {
        dest = "www.aliyun.com:443";
        serverNames = ["www.aliyun.com"];
      };

      reality = target: privateKey: shortId: {
        network = "tcp";
        security = "reality";
        realitySettings =
          target
          // {
            show = false;
            inherit privateKey;
            shortIds = [shortId];
          };
      };

      vision = id: {
        inherit id;
        flow = "xtls-rprx-vision";
      };

      vlessIn = tag: port: clients: streamSettings: {
        inherit tag port streamSettings;
        protocol = "vless";
        settings = {
          inherit clients;
          decryption = "none";
        };
      };
    in
      builtins.toJSON {
        log.loglevel = "warning";

        reverse.portals = [
          {
            tag = "portal-r2s";
            domain = "reverse-r2s.hank.internal";
          }
        ];

        inbounds = [
          (vlessIn "interconn2" 2444
            [(vision s."xray/interconn2_uuid")]
            (reality aliyun s."xray/reality_private_key" s."xray/interconn2_short_id"))

          (vlessIn "client-in2" 54322
            [(vision s."xray/client_in2_uuid")]
            (reality aliyun s."xray/reality_private_key" s."xray/client_in2_short_id"))
        ];

        outbounds = [
          {
            tag = "direct";
            protocol = "freedom";
          }
        ];

        routing.rules = [
          {
            type = "field";
            inboundTag = ["interconn2" "client-in2"];
            outboundTag = "portal-r2s";
          }
        ];
      };
  };

  time.timeZone = "Asia/Hong_Kong";
  i18n.defaultLocale = "en_US.UTF-8";

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
  # Delta only: this option merges definitions, so root arrives from nixpkgs'
  # nix module and the host's usernames from system/modules/nix-settings.nix.
  nix.settings.trusted-users = [
    "nixos"
    "@wheel"
  ];
  system.stateVersion = "25.11";
}
