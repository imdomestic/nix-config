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
    address = "10.0.0.4/24";
  };
in {
  imports = [
    ./hardware-configuration.nix
    # dae -> mihomo。三者不能并存:都要接管转发流量,dae 走 eBPF/tc,
    # mihomo 和 sing-box 走 nftables+tun。回滚就是把 dae 换回来再 switch,
    # 或者直接 nixos-rebuild --rollback。
    # ../../modules/dae
    ../../modules/mihomo
    # sing-box 那次试点已回滚(2026-07-31 凌晨断网),两个坑都没解决,
    # 见 docs/proxy-todo.md 第 5 节。
    # ../../modules/singbox
    ../../modules/keyd
  ];

  # 用 vernesong fork 的 smart 策略组:实测这台到 r5sjp 的链路里,h610 那条
  # RTT 89ms 看着健康但吞吐只有 4.8 Mbit/s、丢包 13%,纯延迟指标分辨不出来,
  # 约 1/5 的流量会被送进去。smart 同时看 latency 和 lossRate。
  my.mihomo.smart = true;
  # 这台是网关,要接管 LAN 转发流量。
  my.mihomo.router = true;
  # metacubexd 面板: http://100.64.0.5:9090/ui —— 只绑 tailscale,
  # 这台 firewall.enable = false,绑 0.0.0.0 等于挂公网上。
  my.mihomo.controllerAddress = "100.64.0.5:9090";

  # 重新启用 modules/singbox 时,这台要一并加上
  #   my.singbox.autoRedirect = false;
  # 电信 PPPoE 给的是 CGNAT 地址(100.84.115.12),和 tailscale 认领的
  # 100.64.0.0/10 撞在一起。但注意 false 本身也有问题(TCP 不进 tun),
  # 两个坑都记在 docs/proxy-todo.md 第 5 节。

  sops.secrets."wireguard/private_key".owner = "systemd-network";
  sops.secrets."wireguard/preshared_key".owner = "systemd-network";

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.kernelModules = ["pppoe"];

  # 根要搬到 SD 卡(mmcblk0)上的 f2fs。**这一步只是把能力装上**,根还在 eMMC
  # 的 ext4 上;真正切换是改 hardware-configuration.nix 里的 UUID。
  #
  # 为什么是 f2fs:这张卡上报 `DISC-GRAN = 4M`,擦除块 4 MB。ext4 那种就地更新
  # 的小块 fsync 落进 4 MB 块里要读-改-写整块;f2fs 是 log-structured,顺序写进
  # segment,正是冲着这个形态设计的(Android 上跑了十亿台设备的也是它)。
  #
  # initrd 里必须有,否则 stage-1 挂不上根 —— 而 r6s 无头,挂不上就是全家断网
  # 且没人能进去。回退路径见 docs/ 里的迁移记录:eMMC 上的 ext4 根原封不动留着,
  # 旧的 generation 各自带自己的 stage-1,从引导菜单选回去就能起来。
  boot.supportedFilesystems = ["f2fs"];
  boot.initrd.supportedFilesystems = ["f2fs"];

  # 强制在 initrd 里插入 f2fs,而不是依赖 mount(2) 触发的按需自动加载。
  # 运行中的系统实测自动加载是好的,但 initrd 用的是 modules-shrunk 树,
  # 少一个不确定变量 —— 这条路上出问题的代价是无头机器起不来。
  boot.initrd.kernelModules = ["f2fs"];

  # ESP 只有 599M,每代 kernel + initrd 约 32M,10 代最坏 640M —— 装不下。
  # 5 代够回退,最坏约 320M;加上 eMMC 救援入口那份 94M,当前占用 38%。
  #
  # **注意 ESP 上还有一份不受 NixOS 管理的 eMMC 救援入口**(/boot/EFI/rescue/),
  # 它是 SD 卡挂掉时唯一的回家路,不会被这个 limit 裁掉。用法、重建步骤、以及
  # 引导相关的两个坑(EFI 变量不持久、别写显式 default)见
  # docs/runbooks/r6s.md。
  #
  # 2026-08-15 清理过一次:`/boot/nixos` + `/boot/extlinux` 是 r2s 时代的遗留
  # (extlinux.conf 里引用的是 rk3328-nanopi-r2s.dtb),382M 死重,占了 ESP 的
  # 三分之二。generic-extlinux-compatible 已经是 false、不再生成,所以搬走即可,
  # 搬到了 /var/lib/stale-boot-backup。清理后 /boot 从 91% 降到 28%。
  boot.loader.systemd-boot.configurationLimit = 5;
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
      trustedInterfaces = ["br-lan" "end0"];
      interfaces."ppp0".allowedUDPPorts = [546];
      checkReversePath = false;
    };
  };

  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
    "net.core.default_qdisc" = "fq";
    "net.ipv4.tcp_congestion_control" = "bbr";

    "net.core.netdev_max_backlog" = 16384; # 增加网卡接收数据包队列
    "net.core.rps_sock_flow_entries" = 32768; # 全局 RFS 流表大小
    "net.ipv4.tcp_fastopen" = 3; # 开启 TCP Fast Open
    "net.ipv4.tcp_mtu_probing" = 1; # 应对黑洞路由，自动探测 MTU

    # TCP buffer (千兆/2.5G 接口建议增大)
    "net.core.rmem_max" = 16777216;
    "net.core.wmem_max" = 16777216;
    "net.ipv4.tcp_rmem" = "4096 87380 16777216";
    "net.ipv4.tcp_wmem" = "4096 65536 16777216";

    # 连接跟踪表 (做路由器跑代理时容易爆)
    "net.netfilter.nf_conntrack_max" = 1048576;
    "net.netfilter.nf_conntrack_buckets" = 262144;
    "net.netfilter.nf_conntrack_tcp_timeout_established" = 7440;

    # 减少 TIME_WAIT
    "net.ipv4.tcp_tw_reuse" = 1;
    "net.ipv4.tcp_fin_timeout" = 15;
  };

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

        if [ -d /sys/class/net/enP3p49s0/queues/rx-0 ]; then
          echo f0 > /sys/class/net/enP3p49s0/queues/rx-0/rps_cpus
        fi

        if [ -d /sys/class/net/enP4p65s0/queues/rx-0 ]; then
          echo f0 > /sys/class/net/enP4p65s0/queues/rx-0/rps_cpus
        fi

        if [ -d /sys/class/net/end0/queues/rx-0 ]; then
          echo f0 > /sys/class/net/end0/queues/rx-0/rps_cpus
        fi

        ${pkgs.ethtool}/bin/ethtool -K end0 gro on gso on tso on
        ${pkgs.ethtool}/bin/ethtool -K enP3p49s0 gro on gso on tso on
        ${pkgs.ethtool}/bin/ethtool -K enP4p65s0 gro on gso on tso on

        # 增大 ring buffer（看硬件支持的最大值）
        ${pkgs.ethtool}/bin/ethtool -G end0 rx 1024 tx 1024 || true
      '';
    };
  };

  services.pppd = {
    enable = true;
    peers = {
      telecom = {
        autostart = true;
        enable = true;
        config = ''
          plugin pppoe.so enP3p49s0
          user "wx10158998"
          password "14725836"

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

    # wireguard
    netdevs."40-wg0" = wg.netdev;
    networks."40-wg0" = wg.network;

    # LAN1
    networks."20-lan1-uplink" = {
      matchConfig.Name = "end0";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    # LAN2
    networks."20-lan2-uplink" = {
      matchConfig.Name = "enP4p65s0";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    networks."20-wan-uplink" = {
      matchConfig.Name = "enP3p49s0";
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

        # **关掉 IPv6 隐私扩展。** 这台和 rpi4 之间的直连只能走 IPv6(两边
        # 的 WAN v4 都是电信 CGNAT,被对方 tailscale 的反欺骗规则丢掉),而
        # 隐私扩展让临时地址定期轮换,tailscale 通告的端点跟着失效,直连就
        # 周期性掉回 DERP。取舍和实测抓到的地址见
        # docs/incidents.md#r6s-rpi4-ipv6-privacy。
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
        Address = "192.168.22.1/24";
        # DHCPv4 Server
        DHCPServer = true;
        # IPv4 NAT
        IPMasquerade = "ipv4";
        # IPv6 RA (SLAAC)
        IPv6SendRA = true;
        IPv6AcceptRA = false;
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
      ipv6SendRAConfig = {
        Managed = false; # no DHCPv6
        OtherInformation = false;
        EmitDNS = true; # send DNS with RA
      };
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
                  - r6s:imdomestic.com
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
    description = "ddns-go";

    wantedBy = ["multi-user.target"];
    wants = ["network-online.target"];
    after = ["network-online.target"];

    serviceConfig = {
      ExecStart = "${pkgs.ddns-go.outPath}/bin/ddns-go -f 300 -c ${config.sops.templates."ddns-go-config.yaml".path}";
      Restart = "always";
      RestartSec = 5;
    };
  };

  services.dnsmasq.enable = false;
  services.resolved = {
    enable = true;
    settings.Resolve = {
      FallbackDNS = ["223.5.5.5"];
      DNSSEC = "false";
      DNSStubListener = "yes";
      DNSStubListenerExtra = ["192.168.22.1" "::"];
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
            tag = "portal-r6s";
            domain = "reverse-r6s.hank.internal";
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
            outboundTag = "portal-r6s";
          }
        ];
      };
  };

  # node_exporter 挪到 nixos/modules/telemetry(经 profiles/server.nix 引入)。
  # 这里原来那份是 openFirewall = true + 默认 listenAddress 0.0.0.0 —— 而这台
  # firewall.enable = false,openFirewall 是空操作,exporter 实际听在包括 ppp0
  # 在内的每一张网卡上。开了 systemd collector 之后它会导出全部 unit 名字,
  # 对这台跑 xray/mihomo 的机器来说那是一份不该外泄的服务清单。
  # 新模块绑 my.host.tsIp(100.64.0.5),和上面 mihomo 面板同一个规矩。

  services.displayManager.gdm.enable = false;
  services.desktopManager.gnome.enable = false;

  # tailscale + Tailscale SSH 由 nixos/modules/tailscale 统一管(经 base profile
  # 引入,按 my.host.tsIp 自动开)。这台是 2026-08-08 那次 Tailscale SSH 的试点,
  # 实测结论记在模块的文件头注释里。

  # programs = {
  #   niri = {
  #     package = pkgs.niri;
  #     enable = true;
  #   };
  #   firefox.enable = true;
  # };

  # Set your time zone.
  time.timeZone = "Asia/Hong_Kong";

  i18n.defaultLocale = "en_US.UTF-8";

  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users.hank = {
    isNormalUser = true;
    extraGroups = ["wheel"]; # Enable ‘sudo’ for the user.
    packages = with pkgs; [
      tree
    ];
  };

  security.sudo.wheelNeedsPassword = false;

  # 整块搬去了 profiles/netdiag.nix —— 这台原本声明的五个里,iproute2 和
  # tailscale 本来就有,剩下三个和另外四台路由器一字不差。

  programs.zsh.enable = true;

  services.openssh.enable = true;

  system.stateVersion = "26.05";
}
