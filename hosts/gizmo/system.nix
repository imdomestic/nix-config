{
  inputs,
  pkgs,
  config,
  lib,
  ...
}: let
  cliproxy = import ../../lib/cliproxy-models.nix {placement = config.my.fleet.placements.cliproxy;};
in {
  imports = [
    ../../system/modules/keyd
    ../../system/modules/vlmcsd
    ../../system/modules/cliproxy
  ];

  # 上游请求本来就从这台出境;放在这里,国内的调用方只跨一次境,海外的不再绕进
  # 国内。见 docs/decisions.md#cliproxy-on-gizmo。只绑 tailscale 地址,理由见
  # 模块里 bindAddress 的说明。
  services.cliproxy = {
    enable = true;
    bindAddress = config.my.host.tsName;
    settings.openai-compatibility = [
      {
        name = "opencode-go";
        prefix = "opencode";
        base-url = cliproxy.opencode.baseUrl;
        api-key-entries = [{api-key = config.sops.placeholder."cliproxy/opencode_api_key";}];
        headers = {
          User-Agent = "CLIProxyAPI-OpenCode-Go/1.0";
          # Derive a conversation ID when clients omit one; never share a fixed session.
          x-opencode-session = "$CPA-SESSION-ID";
        };
        models = lib.mapAttrsToList (id: model:
          {
            name = id;
            alias = id;
            display-name = model.name;
            max-context-length = model.context;
            input-modalities = model.modalities;
            output-modalities = ["text"];
          }
          // lib.optionalAttrs (model ? efforts) {thinking.levels = model.efforts;})
        cliproxy.opencode.models;
      }
    ];
    rewind = {
      enable = true;
      balance.enable = true;
      apiKeyFile = config.sops.secrets."rewind/api_key".path;
    };
  };
  my.tailscale.bindServices = ["cliproxy"];
  sops.secrets."rewind/api_key" = {
    owner = "cliproxy";
    restartUnits = ["cliproxy.service"];
  };
  sops.secrets."cliproxy/opencode_api_key" = {
    owner = "cliproxy";
    restartUnits = ["cliproxy.service"];
  };

  security.acme = {
    acceptTerms = true;
    defaults.email = "hankchogan@gmail.com";
  };

  fileSystems = {
    "/" = {
      device = "/dev/disk/by-label/NIXOS";
      fsType = "ext4";
      options = ["noatime" "commit=60"];
    };
  };

  # 保护 eMMC 颗粒 + 本地重启诊断：
  # 日常流水账全量通过 systemd-journal-upload 实时推送到 tank (14T 存储)；
  # 本地 eMMC 仅持久化 notice/warning/err 关键事件，且 5 分钟批量落盘一次，两端互为备份且零刷盘磨损。
  services.journald.extraConfig = ''
    Storage=persistent
    MaxLevelStore=notice
    SyncIntervalSec=5m
    SystemMaxUse=100M
  '';

  # 方案 3：实时流式推送日志到中央 tank 存储服务器(14T 大空间)
  services.journald.upload = {
    enable = true;
    settings.Upload = {
      URL = "http://tank.inner.imdomestic.com:19532";
      NetworkTimeoutSec = "30s";
    };
  };
  systemd.services.systemd-journal-upload = {
    after = ["tailscaled.service"];
    wants = ["tailscaled.service"];
  };

  # 方案 2：启用 systemd-pstore 自动归档内核崩溃堆栈
  systemd.services.systemd-pstore.enable = true;

  # 抑制高频计时任务在 journal 中反复刷 session scope 启停审计
  systemd.services.tailscale-path-metrics.serviceConfig.LogLevelMax = "warning";
  systemd.services.tailscale-device-rtt.serviceConfig.LogLevelMax = "warning";

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
      "panic=10" # Panic 时保留现场 10 秒供日志和网络处理，随后自动重启
    ];
    kernel.sysctl = {
      "kernel.panic_on_oops" = 1;
      "kernel.panic" = 10;
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

  # 见 profiles/netdiag.nix。iproute2 / tailscale 是冗余声明,删了。
  # wakeonlan 搬去了 home/hank —— 是人用的,机器自己不需要。

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

  networking = {
    firewall = {
      enable = true;
      # 这台不是网关,br-lan 是上行口(带公网 IPv6),不信任任何网卡;要放的
      # 端口由各模块自己声明(vlmcsd、ddns-go、telemetry)。
      # tailscale 子网路由和 xray 桥接走策略路由,rpfilter 会误杀。
      checkReversePath = false;
    };
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
  sops.secrets."xray/peers/sh/uuid" = {};
  sops.secrets."xray/peers/sh/public_key" = {};
  sops.secrets."xray/peers/sh/short_id" = {};
  sops.secrets."xray/peers/r5s/uuid" = {};
  sops.secrets."xray/peers/r5s/public_key" = {};
  sops.secrets."xray/peers/r5s/short_id" = {};
  sops.secrets."xray/peers/r6s/uuid" = {};
  sops.secrets."xray/peers/r6s/public_key" = {};
  sops.secrets."xray/peers/r6s/short_id" = {};
  sops.secrets."xray/peers/r2s/uuid" = {};
  sops.secrets."xray/peers/r2s/public_key" = {};
  sops.secrets."xray/peers/r2s/short_id" = {};

  services.xray.enable = true;
  services.xray.settingsFile = config.sops.templates."xray-config.json".path;

  sops.templates."xray-config.json" = {
    restartUnits = ["xray.service"];
    content = let
      s = config.sops.placeholder;

      # 每个 portal 一条 outbound:gizmo 主动拨过去,把反向隧道建起来。
      # dest 和客户端 sni 必须同时变,没有只加不改的路径。先拿 rpi4 做过金丝雀
      # (30/30 建连成功、零握手错误)才推平其余几台。
      aliyun = "www.aliyun.com";

      interconn = tag: address: port: serverName: uuid: publicKey: shortId: {
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
            inherit serverName;
            fingerprint = "chrome";
            inherit publicKey shortId;
          };
        };
      };

      peer = host: address: port: serverName:
        interconn "interconn-${host}" address port serverName
        s."xray/peers/${host}/uuid"
        s."xray/peers/${host}/public_key"
        s."xray/peers/${host}/short_id";

      # rpi4 不在这里 —— 2026-09-01 它从 portal 改成了第二个 bridge(悉尼
      # 出口),不再有公网入口可拨。理由见 docs/decisions.md#rpi4-portal-to-bridge。
      hosts = ["h610" "sh" "r5s" "r6s" "r2s"];
    in
      builtins.toJSON {
        log = {
          loglevel = "warning";
          access = "none";
        };

        reverse.bridges =
          map (h: {
            tag = "bridge-${h}";
            domain = "reverse-${h}.hank.internal";
          })
          hosts;

        outbounds = [
          (peer "h610" "h610.imdomestic.com" 1444 aliyun)
          (peer "sh" "sh.imdomestic.com" 3444 aliyun)
          (peer "r5s" "r5s.imdomestic.com" 2444 aliyun)
          (peer "r6s" "r6s.imdomestic.com" 2444 aliyun)
          (peer "r2s" "r2s.imdomestic.com" 2444 aliyun)
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

  my.ddns = {
    enable = true;
    zones = [
      {
        ipv4.interface = "br-lan";
        ipv6.interface = "br-lan";
      }
    ];
  };

  programs.zsh.enable = true;

  nixpkgs.hostPlatform = "aarch64-linux";
  system.stateVersion = "26.05";
}
