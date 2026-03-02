{
  inputs,
  config,
  lib,
  pkgs,
  ...
}: let
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
                - r6s:imdomestic.com
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
  imports = [
    ./hardware-configuration.nix
    ../../modules/dae
    # ../../modules/singbox
    ../../modules/tuigreet
    ../../modules/keyd
  ];

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.kernelPackages = pkgs.linuxPackages_latest;
  powerManagement.cpuFreqGovernor = "performance";

  networking = {
    hostName = "r6s"; # Define your hostname.
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
    wg-quick.interfaces = {
      wg0 = {
        configFile = "${inputs.wg-config.outPath}/client_00003.conf";
        autostart = true;
      };
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
          echo ff > /sys/class/net/enP3p49s0/queues/rx-0/rps_cpus
        fi

        if [ -d /sys/class/net/enP4p65s0/queues/rx-0 ]; then
          echo ff > /sys/class/net/enP4p65s0/queues/rx-0/rps_cpus
        fi

        if [ -d /sys/class/net/end0/queues/rx-0 ]; then
          echo ff > /sys/class/net/end0/queues/rx-0/rps_cpus
        fi
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
          plugin pppoe.so end0
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

    # LAN1
    networks."20-lan1-uplink" = {
      matchConfig.Name = "enP3p49s0";
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
      matchConfig.Name = "end0";
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
  systemd.services.ddns-go = {
    enable = true;
    description = "ddns-go";

    wantedBy = ["multi-user.target"];
    wants = ["network-online.target"];
    after = ["network-online.target"];

    serviceConfig = {
      ExecStart = "${pkgs.ddns-go.outPath}/bin/ddns-go -f 300 -c ${ddnsConfig}";
      Restart = "always";
      RestartSec = 5;
    };
  };

  services.dnsmasq.enable = false;
  services.resolved = {
    enable = true;
    dnssec = "false";
    fallbackDns = ["223.5.5.5"];
    extraConfig = ''
      # DNS=127.0.0.1:1053
      # Domains=~.
      DNSStubListener=yes
      DNSStubListenerExtra=192.168.22.1
      DNSStubListenerExtra=::
    '';
  };

  services.prometheus.exporters.node = {
    enable = true;
    openFirewall = true;
    enabledCollectors = ["systemd" "netdev" "netstat"];
    port = 9100;
  };

  services.displayManager.gdm.enable = false;
  services.desktopManager.gnome.enable = false;

  services.cockpit.enable = lib.mkForce false;
  services.tailscale.enable = true;

  # programs = {
  #   niri = {
  #     package = pkgs.niri;
  #     enable = true;
  #   };
  #   firefox.enable = true;
  # };

  # Set your time zone.
  time.timeZone = "Asia/Shanghai";

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

  environment.systemPackages = with pkgs; [
    tcpdump
    iproute2
    ethtool
    mtr
    tailscale
  ];

  programs.zsh.enable = true;

  services.pipewire.enable = true;

  services.openssh.enable = true;

  system.stateVersion = "25.11";
}
