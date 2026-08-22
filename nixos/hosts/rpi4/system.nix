{
  inputs,
  config,
  lib,
  pkgs,
  ...
}: let
  wg = import ../../../lib/wgClient.nix {inherit pkgs;} {
    privateKeyFile = config.sops.secrets."wireguard/private_key".path;
    presharedKeyFile = config.sops.secrets."wireguard/preshared_key".path;
    address = "10.0.0.6/24";
  };
in {
  imports = [
    ./hardware-configuration.nix
    # ../../modules/mihomo
    ../../modules/dae
    # ../../modules/singbox
    # tuigreet 摘掉了。它是个图形登录管理器(services.greetd),而 NixOS 26.05 里
    # greetd 算 displayManager —— 一开就把 graphical-desktop.nix 整个拉进来。
    # **这才是这台上 nautilus 和 speech-dispatcher 的真正来源**,不是 niri:
    # why-depends 的链路是 `etc → dbus-1 → nautilus` 和 `etc →
    # speech-dispatcher → mbrola → mbrola-voices(645 MiB)`,两条都从
    # graphical-desktop 的 dbus/portal 包集出来。
    #
    # 这台没有显示器,登录走串口/ssh,agetty 的默认登录提示完全够用。
    # tank 和 x470 是真桌面,它们那两处的 tuigreet 不动。
    ../../modules/keyd
  ];

  boot.loader.grub.enable = false;
  boot.loader.generic-extlinux-compatible.enable = true;
  boot.kernelPackages = pkgs.linuxPackages_6_12;
  powerManagement.cpuFreqGovernor = "performance";

  networking = {
    networkmanager.enable = false; # Easiest to use and most distros use this by default.
    useDHCP = false;
    useNetworkd = true;
    nftables = {
      enable = true;
      tables.mss-clamping = {
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
    firewall = {
      enable = false;
      checkReversePath = false;
    };
  };

  boot.kernel.sysctl = {
    # NixOS 按配置里的内核生成 /etc/sysctl.d/55-nixos-aslr-entropy.conf，mainline
    # aarch64 (VA_BITS=48) 写 33，而树莓派官方内核 (VA_BITS=39) 上限只有 24。在两者
    # 之间切换时旧内核会拒绝 33，systemd-sysctl 失败进而让 deploy-rs 回滚。24 在两个
    # 内核上都合法；60-nixos.conf 排在 55 之后，会覆盖掉那个值。
    "vm.mmap_rnd_bits" = 24;

    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
    "net.core.default_qdisc" = "fq";
    "net.ipv4.tcp_congestion_control" = "bbr";
  };

  services.pppd = {
    enable = true;
    peers = {
      chinamobile = {
        autostart = true;
        enable = true;
        config = ''
          plugin pppoe.so enp1s0u2
          user "15861587760"
          password "512907"

          # usepeerdns

          defaultroute
          persist
          maxfail 0
          holdoff 5
          noipdefault
          noauth
          hide-password
          lcp-echo-interval 30
          lcp-echo-failure 20
          lcp-echo-adaptive

          +ipv6
          ipv6cp-use-ipaddr

          mtu 1492
          mru 1492
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

    networks."20-lan-uplink" = {
      matchConfig.Name = "end0";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    networks."20-wan-uplink" = {
      matchConfig.Name = "enp1s0u2";
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

        # 关掉 IPv6 隐私扩展,理由见 hosts/r6s/system.nix 里同一处的长注释。
        # 简版:这台的 WAN v4 是 100.112.172.41,r6s 是 100.84.115.12,双双
        # 落在 tailscale 认领的 100.64.0.0/10 里,互相被对方的反欺骗规则丢包,
        # 所以这一对只能靠 IPv6 直连;而临时地址轮换会让那条直连周期性断。
        # 这台尤其明显 —— ppp0 上一度积了 8 个全局 v6 地址,好几个已 deprecated。
        IPv6PrivacyExtensions = "no";
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

  services.dnsmasq.enable = false;
  services.resolved = {
    enable = true;
    settings.Resolve = {
      FallbackDNS = ["223.5.5.5"];
      DNSStubListener = "yes";
      DNSStubListenerExtra = ["192.168.20.1" "::"];
    };
  };
  # services.irqbalance.enable = true;
  services.udev.extraRules = ''
    ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="0bda", ATTR{idProduct}=="8156", ATTR{power/control}="on"
  '';
  boot.kernelParams = ["usbcore.autosuspend=-1"];

  # node_exporter 挪到 nixos/modules/telemetry(经 profiles/server.nix 引入)。
  # 同 r6s:这台也是 firewall.enable = false,原来那份 openFirewall = true
  # 是空操作,exporter 实际绑在 0.0.0.0。新模块绑 my.host.tsIp(100.64.0.7)。

  # ddns-go cloudflare token + web password rendered from sops.
  sops.secrets."wireguard/private_key".owner = "systemd-network";
  sops.secrets."wireguard/preshared_key".owner = "systemd-network";
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
                  - rpi4:imdomestic.com
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
        log.loglevel = "warning";

        reverse.portals = [
          {
            tag = "portal-rpi4";
            domain = "reverse-rpi4.hank.internal";
          }
        ];

        inbounds = [
          # r5sjp 的 bridge 拨进来的新落点(Step 4 切换)。
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

        # 四个入口一律丢进反向隧道,从 r5sjp 的日本出口出去。
        routing.rules = [
          {
            type = "field";
            inboundTag = ["interconn2" "client-in2"];
            outboundTag = "portal-rpi4";
          }
        ];
      };
  };

  services.displayManager.gdm.enable = false;
  services.desktopManager.gnome.enable = false;

  systemd.services.network-tuning = {
    description = "Optimize Network Performance (RPS)";
    wantedBy = ["multi-user.target"];
    wants = ["network-online.target"];
    after = ["network-online.target"];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = pkgs.writeScript "enable-rps" ''
        #!${pkgs.bash}/bin/bash

        if [ -d /sys/class/net/enp1s0u2/queues/rx-0 ]; then
          echo f > /sys/class/net/enp1s0u2/queues/rx-0/rps_cpus
        fi

        if [ -d /sys/class/net/end0/queues/rx-0 ]; then
          echo f > /sys/class/net/end0/queues/rx-0/rps_cpus
        fi
      '';
    };
  };

  # 原本开着 niri + firefox,2026-08-12 清掉 —— 这台是网关、没接显示器,那套
  # 桌面栈从来没人用过,却往 closure 里拖了 2 GiB(明细见
  # docs/decisions.md#rpi4-drop-desktop)。
  #
  # 下面 gdm/gnome 的两个显式 false 留着:它们是"这台不要桌面"的意图声明,不是
  # 对某个 profile 的覆盖。真有人手滑加回 desktop profile,那两行会挡一下。

  time.timeZone = "Asia/Hong_Kong";

  i18n.defaultLocale = "en_US.UTF-8";

  users.users.hank = {
    isNormalUser = true;
    extraGroups = ["wheel"]; # Enable ‘sudo’ for the user.
    packages = with pkgs; [
      tree
    ];
  };

  security.sudo.wheelNeedsPassword = false;

  # 见 profiles/netdiag.nix。iproute2 是冗余声明,删了。
  # ddns-go 删了:上面那个单元写的是 ${pkgs.ddns-go.outPath}/bin/ddns-go,
  # 走绝对 store 路径,不吃 PATH。

  programs.zsh.enable = true;

  # pipewire 跟着上面那套桌面一起删了 —— 这台没有声卡也没有人在上面放音频,
  # 它存在的唯一原因是 niri 那套需要。

  # services.openssh.enable 删了:profiles/server.nix → modules/ssh 已经开了,
  # 而且那边还配了 AuthorizedKeysFile 指向 /etc/ssh/authorized_keys.d/master。
  # 在这里再写一遍只会让人以为有两个来源。
  system.stateVersion = "25.05"; # Did you read the comment?
}
