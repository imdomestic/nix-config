{
  inputs,
  pkgs,
  ...
}: let
  domainName = "sh.imdomestic.com";
  listenPort = "8443";
  certFile = "/etc/nixos/certs/sh.imdomestic.com.pem";
  keyFile = "/etc/nixos/certs/sh.imdomestic.com.key";
in {
  imports = [
    ./hardware-configuration.nix
    ../../modules/dae
  ];

  networking.hostName = "shanghai";
  networking.domain = "";
  time.timeZone = "Asia/Shanghai";

  boot.loader.grub.enable = true;
  boot.loader.grub.useOSProber = false;
  boot.tmp.cleanOnBoot = true;
  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
    "net.core.default_qdisc" = "fq";
    "net.ipv4.tcp_congestion_control" = "bbr";
  };
  zramSwap.enable = true;

  users.users.root.openssh.authorizedKeys.keys = [
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDgKVrXIcm6y0r6KWHSBCNfftsShgy/dTdkQBo4YNuZjq0fxd/AtxZRELfFFuJbA5OaT6XZPLvf6c9gh9wrUGY1gdW1qhtDEgvlmGFH05cxgDlktw0BqLWxqjvdyjUvPn+oA526YjhjD8bK4zTPQQ9B0MNUQuY8UGg1VHD+0drgLYZQolqOxRUL15R1aBqEOl885j8pSEGacTv9mDGEZxBhQZKAauo1WN38vPH6Diq8zBz652jNaHedNdHd3zRqXRUGjHLTnKY5Jq7rvAnHdGZlH2STtu4BhLxOEVd6p28VRsLpeuMnz9xpVbgMmiTZvKlj2AFtk2qM8Sb9kHxgSEVTo+w83Rkn18DYinhfgWCP4ikqGs1Q5kgO1O7F32kFngqW0IPRadYtIGE2JHhRPuEzeubETZJQX4AKDYOIFpxXbcK1jBM+rDnhLmfsJh5nC9U/ZP7C6LN+BJuEwhDutK2EGZVC1oZ4cYgnL3V0ip5Ics4i/o2RTk8s5ETdbd/bU1E= ysh2291939848@outlook.com"
  ];

  users.users.hank = {
    isNormalUser = true;
    extraGroups = ["wheel"];
    openssh.authorizedKeys.keys = [
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDgKVrXIcm6y0r6KWHSBCNfftsShgy/dTdkQBo4YNuZjq0fxd/AtxZRELfFFuJbA5OaT6XZPLvf6c9gh9wrUGY1gdW1qhtDEgvlmGFH05cxgDlktw0BqLWxqjvdyjUvPn+oA526YjhjD8bK4zTPQQ9B0MNUQuY8UGg1VHD+0drgLYZQolqOxRUL15R1aBqEOl885j8pSEGacTv9mDGEZxBhQZKAauo1WN38vPH6Diq8zBz652jNaHedNdHd3zRqXRUGjHLTnKY5Jq7rvAnHdGZlH2STtu4BhLxOEVd6p28VRsLpeuMnz9xpVbgMmiTZvKlj2AFtk2qM8Sb9kHxgSEVTo+w83Rkn18DYinhfgWCP4ikqGs1Q5kgO1O7F32kFngqW0IPRadYtIGE2JHhRPuEzeubETZJQX4AKDYOIFpxXbcK1jBM+rDnhLmfsJh5nC9U/ZP7C6LN+BJuEwhDutK2EGZVC1oZ4cYgnL3V0ip5Ics4i/o2RTk8s5ETdbd/bU1E= ysh2291939848@outlook.com"
    ];
  };

  networking = {
    firewall.enable = false;
    networkmanager.enable = false;
    useNetworkd = true;
    useDHCP = false;
    nftables = {
      enable = true;
      tables.cs2 = {
        name = "cs2";
        enable = true;
        family = "inet";
        content = ''
          chain prerouting {
            type nat hook prerouting priority -100; policy accept;

            iifname "br-lan" tcp dport 27015 dnat ip to 10.0.0.66:27015
            iifname "br-lan" udp dport 27015 dnat ip to 10.0.0.66:27015
          }

          chain postrouting {
            type nat hook postrouting priority 100; policy accept;

            oifname "wg0" ip daddr 10.0.0.66 tcp dport 27015 masquerade
            oifname "wg0" ip daddr 10.0.0.66 udp dport 27015 masquerade
          }
        '';
      };
    };
    wg-quick.interfaces = {
      wg0 = {
        configFile = "${inputs.wg-config.outPath}/server.conf";
        autostart = true;
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
      matchConfig.Name = "ens5";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    networks."30-br-lan" = {
      matchConfig.Name = "br-lan";
      networkConfig = {
        DHCP = "yes";
      };
      linkConfig = {
        RequiredForOnline = "routable";
      };
    };
  };

  services.headscale = {
    enable = true;
    address = "127.0.0.1";
    port = 8080;
    settings = {
      server_url = "https://${domainName}:${listenPort}";
      derp.server = {
        enable = true;
        region_id = 999;
        region_code = "sh-aliyun";
        region_name = "Shanghai Aliyun";
        stun_listen_addr = "0.0.0.0:3478";
      };
      dns = {
        base_domain = "inner.imdomestic.com";
        magic_dns = true;
        nameservers = {};
        override_local_dns = false;
      };
      ip_prefixes = ["100.64.0.0/10"];
    };
  };

  services.caddy = {
    enable = true;
    virtualHosts."${domainName}:${listenPort}" = {
      extraConfig = ''
        tls ${certFile} ${keyFile}

        reverse_proxy 127.0.0.1:8080 {
            header_up Host {host}
            header_up X-Real-IP {remote}
            header_up X-Forwarded-For {remote}
            header_up X-Forwarded-Proto {scheme}
            transport http {
                keepalive 300s
            }
        }
      '';
    };
  };

  services.resolved.enable = true;
  services.qemuGuest.enable = true;

  services.iperf3.enable = true;
  services.openssh = {
    enable = true;
  };
  services.openssh.openFirewall = true;
  services.openssh.settings = {
    PasswordAuthentication = true;
    PermitRootLogin = "yes";
  };

  security.sudo.wheelNeedsPassword = false;

  environment.systemPackages = with pkgs; [
    git
    neovim
    fzf
  ];
  environment.pathsToLink = ["/share/applications" "/share/xdg-desktop-portal"];

  programs.zsh.enable = true;
  system.stateVersion = "25.11";
}
