{
  inputs,
  pkgs,
  config,
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
    ../../system/modules/keyd
  ];

  # tank (and Max on it since 2026-09-27) resolves through this gateway:
  # docs/incidents.md#tank-browser-poisoned-dns.
  my.dae.foreignDnsOverTcp = true;
  # ddns-go must reach Cloudflare's API even while the proxy is down.
  my.dae.bootstrapDomains = ["api.cloudflare.com"];

  sops.secrets."wireguard/private_key".owner = "systemd-network";
  sops.secrets."wireguard/preshared_key".owner = "systemd-network";

  fileSystems = {
    "/" = {
      device = "/dev/disk/by-label/NIXOS";
      fsType = "ext4";
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
    };
  };

  time.timeZone = "Asia/Hong_Kong";

  powerManagement.cpuFreqGovernor = "performance";
  services.displayManager.gdm.enable = false;
  services.desktopManager.gnome.enable = false;

  my.ddns.enable = true;


  # vim/tcpdump/ethtool/mtr 搬去了 profiles/netdiag.nix;iproute2 和 tailscale
  # 删掉了 —— 前者 NixOS 本来就给,后者 services.tailscale 自己会装。
  environment.systemPackages = with pkgs; [
    ndppd
  ];

  security.sudo.wheelNeedsPassword = false;
  # Delta only: this option merges definitions, so root arrives from nixpkgs'
  # nix module and the host's usernames from system/modules/nix-settings.nix.
  nix.settings.trusted-users = ["@wheel"];

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

  i18n.defaultLocale = "en_US.UTF-8";

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
      checkRuleset = false;
      tables.router = {
        name = "mss-clamping";
        enable = true;
        family = "inet";
        content = ''
          flowtable f {
            hook ingress priority 0;
            devices = { wan0 };
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
  };
  systemd.network = {
    enable = true;
    netdevs."40-wg0" = wg.netdev;
    networks."40-wg0" = wg.network;
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
        # pppd installs the IPv4 (IPCP) address; keep it across networkd
        # restarts so `nixos-rebuild switch` doesn't flush it.
        KeepConfiguration = "yes";
      };
      linkConfig = {
        RequiredForOnline = "carrier";
      };
      dhcpV6Config = {
        WithoutRA = "solicit";
        PrefixDelegationHint = "::/62";
        UseDelegatedPrefix = true;
      };
    };

    networks."30-br-lan" = {
      matchConfig.Name = "br-lan";
      networkConfig = {
        Address = "192.168.20.1/24";
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
        DNS = ["192.168.20.1"];
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
      echo 32768 > /proc/sys/net/core/rps_sock_flow_entries

      for file in /sys/class/net/enp1s0/queues/rx-*/rps_cpus; do
        echo f > "$file"
      done

      for file in /sys/class/net/enP1p17s0/queues/rx-*/rps_cpus; do
        echo f > "$file"
      done

      for tx in "$dev"/queues/tx-*; do
        echo $mask > "$tx/xps_cpus" 2>/dev/null || true
      done
    '';
  };

  services.pppd = {
    enable = true;
    peers = {
      telecom = {
        autostart = true;
        enable = true;
        config = ''
          plugin pppoe.so wan0
          # user "051002554981"
          # password "741852"
          user "15861587760"
          password "512907"

          # usepeerdns

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

  # Xray 的凭据全部走 sops。内联到 `settings` 会把 UUID 和 Reality 私钥同时写进
  # 这个公开仓库和 world-readable 的 nix store,所以整份 config 改由
  # sops.templates 渲染,再用 settingsFile 交给 xray。xray.service 是
  # DynamicUser + LoadCredential:systemd 先以 root 读取渲染结果,再投给动态用户,
  # 所以 root-only 的 /run/secrets/rendered 够用。
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

      # www.aliyun.com:证书记录 2845B(远低于 REALITY 硬编码的 8192 上限,
      # 见 Xray #6356),解析到本省电信段,dest 拨号不出省。
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
        log.loglevel = "debug";

        reverse.portals = [
          {
            tag = "portal-r5s";
            domain = "reverse-r5s.hank.internal";
          }
        ];

        inbounds = [
          # gizmo 的 bridge 拨进来的新落点(Step 4 切换)。
          (vlessIn "interconn2" 2444
            [(vision s."xray/interconn2_uuid")]
            (reality aliyun s."xray/reality_private_key" s."xray/interconn2_short_id"))

          # 自己用的新入口,凭据与老的完全无关。
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

        # 四个入口一律丢进反向隧道,从 gizmo 的日本出口出去。
        routing.rules = [
          {
            type = "field";
            inboundTag = ["interconn2" "client-in2"];
            outboundTag = "portal-r5s";
          }
        ];
      };
  };

  services.dnsmasq.enable = false;
  services.resolved = {
    enable = true;
    settings.Resolve = {
      FallbackDNS = ["223.5.5.5"];
      DNSStubListener = "yes";
      DNSStubListenerExtra = ["192.168.20.1" "::"];
    };
  };
  services.irqbalance.enable = true;
  services.openssh = {
    enable = true;
    ports = [22 2200];
  };

  programs.zsh.enable = true;

  nixpkgs.hostPlatform = "aarch64-linux";
  system.stateVersion = "26.05";
}
