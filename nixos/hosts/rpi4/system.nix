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
                - rpi4:imdomestic.com
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
    # ../../modules/mihomo
    ../../modules/dae
    ../../modules/tuigreet
    ../../modules/keyd
  ];

  boot.loader.grub.enable = false;
  boot.loader.generic-extlinux-compatible.enable = true;
  boot.kernelPackages = pkgs.linuxPackages_rpi4;
  powerManagement.cpuFreqGovernor = "performance";

  networking = {
    hostName = "rpi4"; # Define your hostname.
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
      chinamobile = {
        autostart = true;
        enable = true;
        config = ''
          plugin pppoe.so enp1s0u2
          user "15861587760"
          password "168168"

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
    fallbackDns = ["223.5.5.5"];
    extraConfig = ''
      DNSStubListener=yes
      DNSStubListenerExtra=192.168.20.1
      DNSStubListenerExtra=::
    '';
  };
  # services.irqbalance.enable = true;
  services.udev.extraRules = ''
    ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="0bda", ATTR{idProduct}=="8156", ATTR{power/control}="on"
  '';
  boot.kernelParams = ["usbcore.autosuspend=-1"];

  services.tailscale = {
    enable = true;
  };

  services.prometheus.exporters.node = {
    enable = true;
    openFirewall = true;
    enabledCollectors = ["systemd" "netdev" "netstat"];
    port = 9100;
  };

  systemd.services.ddns-go = {
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

  services.xray.enable = true;
  services.xray.settings = {
    log.loglevel = "warning";

    reverse = {
      portals = [
        {
          tag = "portal-rpi4";
          domain = "reverse-rpi4.hank.internal";
        }
      ];
    };

    inbounds = [
      {
        tag = "interconn";
        port = 2443;
        protocol = "vless";
        settings = {
          clients = [
            {
              id = "4417cfd8-49e5-4ca3-bcc7-4e80f5f1bb40";
              flow = "xtls-rprx-vision";
            }
          ];
          decryption = "none";
        };
        streamSettings = {
          network = "tcp";
          security = "reality";
          realitySettings = {
            show = false;
            dest = "www.microsoft.com:443";
            serverNames = ["www.microsoft.com" "microsoft.com"];
            privateKey = "OPcQVvCeM3LAYG7axaGuATC8O_QvjqRPKRO74FPjSlg";
            shortIds = ["17"];
          };
        };
      }

      {
        tag = "client-in";
        port = 54321;
        protocol = "vless";
        settings = {
          clients = [
            {
              id = "2cac4128-2151-4a28-8102-ea1806f9c12b";
              flow = "xtls-rprx-vision";
            }
          ];
          decryption = "none";
        };
        streamSettings = {
          network = "tcp";
          security = "reality";
          realitySettings = {
            show = false;
            dest = "www.microsoft.com:443";
            serverNames = ["www.microsoft.com" "microsoft.com"];
            privateKey = "SFXrsyrENIJqHMgk9Chjc-cA4MlzaTOBlF9OBAuSY0w";
            shortIds = ["16"];
          };
        };
      }
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
        inboundTag = ["interconn"];
        outboundTag = "portal-rpi4";
      }

      {
        type = "field";
        inboundTag = ["client-in"];
        outboundTag = "portal-rpi4";
      }
    ];
  };

  services.displayManager.gdm.enable = false;
  services.desktopManager.gnome.enable = false;

  systemd.services.network-tuning = {
    description = "Optimize Network Performance (RPS)";
    wantedBy = ["multi-user.target"];
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

  programs = {
    niri = {
      package = pkgs.niri;
      enable = true;
    };
    firefox.enable = true;
  };

  time.timeZone = "Asia/Shanghai";

  i18n.defaultLocale = "en_US.UTF-8";

  users.users.hank = {
    isNormalUser = true;
    extraGroups = ["wheel"]; # Enable ‘sudo’ for the user.
    packages = with pkgs; [
      tree
    ];
  };

  security.sudo.wheelNeedsPassword = false;

  environment.systemPackages = with pkgs; [
    vim
    tcpdump
    iproute2
    ethtool
    mtr
    ddns-go
  ];

  programs.zsh.enable = true;

  services.pipewire.enable = true;

  services.openssh.enable = true;
  system.stateVersion = "25.05"; # Did you read the comment?
}
