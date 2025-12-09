# Edit this configuration file to define what should be installed on
# your system. Help is available in the configuration.nix(5) man page, on
# https://search.nixos.org/options and in the NixOS manual (`nixos-help`).
{
  inputs,
  config,
  lib,
  pkgs,
  ...
}: {
  imports = [
    # Include the results of the hardware scan.
    ./hardware-configuration.nix
    # ../../modules/mihomo
    ../../modules/dae
    ../../modules/tuigreet
    ../../modules/keyd
  ];

  # Use the extlinux boot loader. (NixOS wants to enable GRUB by default)
  boot.loader.grub.enable = false;
  # Enables the generation of /boot/extlinux/extlinux.conf
  boot.loader.generic-extlinux-compatible.enable = true;
  boot.kernelPackages = pkgs.linuxPackages_rpi4;

  networking = {
    hostName = "rpi4"; # Define your hostname.
    networkmanager.enable = false; # Easiest to use and most distros use this by default.
    useDHCP = false;
    useNetworkd = true;
    nftables.enable = true;
    firewall = {
      enable = true;
      # 信任 LAN 口，方便调试
      trustedInterfaces = ["br-lan"];
      # DHCPv6 rx
      interfaces."ppp0".allowedUDPPorts = [ 546 ];
      # 必须关闭 rpfilter (反向路径过滤)，否则 dae 的透明代理可能会被丢包
      checkReversePath = false;
      extraForwardRules = ''
        # TCP MSS Clamping: 将 TCP 包的大小限制在 PMTU 范围内
        ip protocol tcp tcp flags syn tcp option maxseg size set rt mtu
      '';
    };
    wg-quick.interfaces = {
      wg0 = {
        configFile = "${inputs.wg-config.outPath}/client_00005.conf";
        autostart = true;
      };
    };
  };

  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
    "net.core.default_qdisc" = "fq";
    "net.ipv4.tcp_congestion_control" = "bbr";
  };

  services.pppd = {
    enable = true;
    peers = {
      # 定义拨号连接名称，接口将是 ppp0
      chinamobile = {
        autostart = true;
        enable = true;
        config = ''
          plugin pppoe.so enp1s0u2
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
      matchConfig.Name = "end0";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    # WAN, DHCP
    # networks."20-wan-uplink" = {
    #   matchConfig.Name = "enp1s0u2";
    #   networkConfig = {
    #     DHCP = "yes";
    #     IPv6AcceptRA = true;
    #     # IPMasquerade = "ipv4";
    #   };
    #   linkConfig.RequiredForOnline = "routable";
    #   dhcpV6Config = {
    #     PrefixDelegationHint = "::/60";
    #     UseDelegatedPrefix = true;
    #   };
    # };

    networks."20-wan-uplink" = {
      matchConfig.Name = "enp1s0u2";
      # 只需要链路层启动即可
      linkConfig.RequiredForOnline = "no";
      networkConfig = {
        # 必须禁用链路本地地址，防止干扰
        LinkLocalAddressing = "no";
        DHCP = "no";
        # 这里不需要 IPMasquerade 了，因为它是物理载体
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
      linkConfig.RequiredForOnline = "carrier";
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
        DNS = ["192.168.20.1"]; # 告诉客户端 DNS 找我 (然后被 dae 劫持)
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
  services.resolved.enable = true;
  services.irqbalance.enable = true;
  services.udev.extraRules = ''
    ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="0bda", ATTR{idProduct}=="8156", ATTR{power/control}="on"
  '';
  boot.kernelParams = ["usbcore.autosuspend=-1"];

  # services.tailscale = {
  #   enable = true;
  #   openFirewall = true;
  #   extraUpFlags = ["--accept-dns=false" "--login-server https://sh.imdomestic.com:8443"];
  # }

  services.cockpit = {
    enable = true;
    port = 9090;
    openFirewall = true; # Please see the comments section
    allowed-origins = ["*"];
    settings = {
      WebService = {
        AllowUnencrypted = true;
      };
    };
  };

  services.prometheus.exporters.node = {
    enable = true;
    openFirewall = true;
    enabledCollectors = ["systemd" "netdev" "netstat"];
    port = 9100;
  };

  services.desktopManager.gnome.enable = true;

  programs = {
    niri = {
      package = pkgs.niri;
      enable = true;
    };
    firefox.enable = true;
  };

  # Set your time zone.
  time.timeZone = "Asia/Shanghai";

  # networking.proxy.default = "http://192.168.1.25:7890";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

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

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    vim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
    neovim
    wget
    gcc
  ];

  programs.zsh.enable = true;

  services.pipewire.enable = true;

  services.openssh.enable = true;
  systemd.services.ddns-go = {
    enable = false;
    description = "Simple and easy to use DDNS. Automatically update domain name resolution to public IP (Support Aliyun, Tencent Cloud, Dnspod, Cloudflare, Callback, Huawei Cloud, Baidu Cloud, Porkbun, GoDaddy...)";

    wants = ["network.target"];
    after = ["network-online.target"];

    serviceConfig = {
      StartLimitInterval = 5;
      StartLimitBurst = 10;
      ExecStart = "${pkgs.ddns-go.outPath}/bin/ddns-go \"-l\" \":9876\" \"-f\" \"300\" \"-cacheTimes\" \"5\" \"-c\" \"/home/nix/.ddns_go_config.yaml\"";
      Restart = "always";
      RestartSec = 120;
      EnvironmentFile = "-/etc/sysconfig/ddns-go";
    };

    wantedBy = ["multi-user.target"];
  };

  system.stateVersion = "25.05"; # Did you read the comment?
}
