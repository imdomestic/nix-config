{
  inputs,
  pkgs,
  config,
  ...
}: {
  imports = [
    ../../modules/keyd
    ../../modules/vlmcsd
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

  time.timeZone = "Asia/Hong_Kong";
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
    wakeonlan
  ];

  security.sudo.wheelNeedsPassword = false;
  # Delta only: this option merges definitions, so root arrives from nixpkgs'
  # nix module and the host's usernames from nixos/modules/nix-settings.nix.
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

  i18n.defaultLocale = "en_US.UTF-8";
  # environment.etc = {
  #   "systemd/journald.conf.d/99-storage.conf".text = ''
  #     [Journal]
  #     Storage=volatile
  #   '';
  # };

  networking = {
    firewall.enable = false;
    networkmanager.enable = false;
    useNetworkd = true;
    nftables = {
      enable = true;
      checkRuleset = true;
      tables.google-v4-only = {
        family = "ip6";
        content = ''
          chain output {
            type filter hook output priority 0; policy accept;

            # google
            ip6 daddr 2404:6800::/32 reject with icmpv6 type addr-unreachable
            ip6 daddr 2607:f8b0::/32 reject with icmpv6 type addr-unreachable
            ip6 daddr 2a00:1450::/32 reject with icmpv6 type addr-unreachable
            ip6 daddr 2800:3f0::/32  reject with icmpv6 type addr-unreachable
            ip6 daddr 2c0f:fb50::/32 reject with icmpv6 type addr-unreachable

            # github
            # ip6 daddr 2a0a:a440::/29 reject with icmpv6 type addr-unreachable
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
    settings.Resolve = {
      FallbackDNS = ["223.5.5.5"];
      DNSStubListener = "yes";
      DNSStubListenerExtra = ["::"];
    };
  };
  services.openssh = {
    enable = true;
    ports = [22 2200];
  };

  services.nginx = {
    enable = true;
    clientMaxBodySize = "50m";
  };

  # Xray 的凭据全部走 sops。内联到 `settings` 会把每个 portal 的 UUID 写进这个
  # 公开仓库和 world-readable 的 nix store,所以整份 config 改由 sops.templates
  # 渲染,再用 settingsFile 交给 xray。
  sops.secrets."xray/peers/h610/uuid" = {};
  sops.secrets."xray/peers/h610/public_key" = {};
  sops.secrets."xray/peers/h610/short_id" = {};
  sops.secrets."xray/peers/rpi4/uuid" = {};
  sops.secrets."xray/peers/rpi4/public_key" = {};
  sops.secrets."xray/peers/rpi4/short_id" = {};
  sops.secrets."xray/peers/sh/uuid" = {};
  sops.secrets."xray/peers/sh/public_key" = {};
  sops.secrets."xray/peers/sh/short_id" = {};
  sops.secrets."xray/peers/r5s/uuid" = {};
  sops.secrets."xray/peers/r5s/public_key" = {};
  sops.secrets."xray/peers/r5s/short_id" = {};
  sops.secrets."xray/peers/r6s/uuid" = {};
  sops.secrets."xray/peers/r6s/public_key" = {};
  sops.secrets."xray/peers/r6s/short_id" = {};
  # r2s 离线,仍停在老端口和已泄露的凭据上。它恢复并照其余几台处理之后,
  # 这三个键和下面那条 interconn-r2s 一起删。
  sops.secrets."xray/legacy/uuid" = {};
  sops.secrets."xray/legacy/public_key" = {};
  sops.secrets."xray/legacy/short_id" = {};

  services.xray.enable = true;
  services.xray.settingsFile = config.sops.templates."xray-config.json".path;

  sops.templates."xray-config.json" = {
    restartUnits = ["xray.service"];
    content = let
      s = config.sops.placeholder;

      # 每个 portal 一条 outbound:r5sjp 主动拨过去,把反向隧道建起来。
      interconn = tag: address: port: uuid: publicKey: shortId: {
        inherit tag;
        protocol = "vless";
        settings.vnext = [
          {
            inherit address port;
            users = [
              {
                id = uuid;
                flow = "xtls-rprx-vision";
                encryption = "none";
              }
            ];
          }
        ];
        streamSettings = {
          network = "tcp";
          security = "reality";
          realitySettings = {
            serverName = "www.apple.com";
            fingerprint = "chrome";
            inherit publicKey shortId;
          };
        };
      };

      peer = host: address: port:
        interconn "interconn-${host}" address port
        s."xray/peers/${host}/uuid"
        s."xray/peers/${host}/public_key"
        s."xray/peers/${host}/short_id";

      hosts = ["h610" "rpi4" "sh" "r5s" "r6s" "r2s"];
    in
      builtins.toJSON {
        log.loglevel = "warning";

        reverse.bridges =
          map (h: {
            tag = "bridge-${h}";
            domain = "reverse-${h}.hank.internal";
          })
          hosts;

        outbounds = [
          (peer "h610" "h610.imdomestic.com" 1444)
          (peer "rpi4" "rpi4.imdomestic.com" 2444)
          (peer "sh" "sh.imdomestic.com" 3444)
          (peer "r5s" "r5s.imdomestic.com" 2444)
          (peer "r6s" "r6s.imdomestic.com" 2444)
          (interconn "interconn-r2s" "r2s.imdomestic.com" 2443
            s."xray/legacy/uuid"
            s."xray/legacy/public_key"
            s."xray/legacy/short_id")
          {
            tag = "out";
            protocol = "freedom";
          }
        ];

        routing.rules =
          # 每条隧道的控制信道:发往该 portal 内部域名的流量回到它自己那条 outbound
          map (h: {
            type = "field";
            inboundTag = ["bridge-${h}"];
            domain = ["full:reverse-${h}.hank.internal"];
            outboundTag = "interconn-${h}";
          })
          hosts
          ++ [
            # 其余经隧道进来的流量一律从本机直出 —— 这就是日本出口
            {
              type = "field";
              inboundTag = map (h: "bridge-${h}") hosts;
              outboundTag = "out";
            }
          ];
      };
  };

  # ddns-go cloudflare token + web password rendered from sops.
  sops.secrets."ddns/cloudflare_token" = {};
  sops.secrets."ddns/web_password" = {};
  sops.templates."ddns-go-config.yaml" = {
    restartUnits = ["ddns-go.service"];
    content = ''
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
              secret: ${config.sops.placeholder."ddns/cloudflare_token"}
            ttl: ""
      user:
          username: hank
          password: ${config.sops.placeholder."ddns/web_password"}
      webhook:
          webhookurl: ""
          webhookrequestbody: ""
          webhookheaders: ""
      notallowwanaccess: false
      lang: zh
    '';
  };

  systemd.services.ddns-go = {
    enable = true;
    description = "ddns";

    wantedBy = ["multi-user.target"];
    wants = ["network-online.target"];
    after = ["network-online.target"];

    serviceConfig = {
      ExecStart = "${pkgs.ddns-go.outPath}/bin/ddns-go -f 300 -c ${config.sops.templates."ddns-go-config.yaml".path}";
      Restart = "always";
      RestartSec = 5;
    };
  };

  services.tailscale.enable = true;

  programs.zsh.enable = true;

  nixpkgs.hostPlatform = "aarch64-linux";
  system.stateVersion = "26.05";
}
