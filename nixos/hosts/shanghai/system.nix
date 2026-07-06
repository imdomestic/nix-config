{
  inputs,
  pkgs,
  lib,
  config,
  ...
}: let
  wgPeers = import ./wg-peers.nix;
  wg = import ../../../lib/wgServer.nix {inherit pkgs lib;} {
    peers = wgPeers;
    privateKeyFile = config.sops.secrets."wireguard/private_key".path;
    pskFileFor = idx: config.sops.secrets."wireguard/psk/${toString idx}".path;
    address = "10.0.0.1/24";
  };
in {
  imports = [
    ./hardware-configuration.nix
    ../../modules/dae
    ../../modules/minecraft/sh.nix
  ];

  sops.secrets =
    {
      "wireguard/private_key".owner = "systemd-network";
      "xray/vless_uuid" = {};
      "xray/interconn_private_key" = {};
      "xray/client_private_key" = {};
      "k3s/token" = {};
    }
    // lib.listToAttrs (lib.imap0 (idx: _: {
        name = "wireguard/psk/${toString idx}";
        value = {owner = "systemd-network";};
      })
      wgPeers);

  networking.hostName = "shanghai";
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

            iifname "br-lan" tcp dport 64738 dnat ip to 10.0.0.66:64738
            iifname "br-lan" udp dport 64738 dnat ip to 10.0.0.66:64738
          }

          chain postrouting {
            type nat hook postrouting priority 100; policy accept;

            oifname "wg0" ip daddr 10.0.0.66 tcp dport 27015 masquerade
            oifname "wg0" ip daddr 10.0.0.66 udp dport 27015 masquerade

            oifname "wg0" ip daddr 10.0.0.66 tcp dport 64738 masquerade
            oifname "wg0" ip daddr 10.0.0.66 udp dport 64738 masquerade
          }
        '';
      };
      # Replaces the server.conf PostUp:
      #   iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
      # so WireGuard clients (10.0.0.0/24) reach the internet via the WAN (br-lan).
      tables.wireguard = {
        name = "wireguard";
        enable = true;
        family = "inet";
        content = ''
          chain postrouting {
            type nat hook postrouting priority 100; policy accept;

            ip saddr 10.0.0.0/24 oifname "br-lan" masquerade
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

    networks."20-lan-uplink" = {
      matchConfig.Name = "ens5";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    networks."30-br-lan" = {
      matchConfig.Name = "br-lan";
      networkConfig = {
        DHCP = "yes";
        # The ISP's DHCP hands out DNS servers inside 100.64.0.0/10 (CGNAT),
        # the same range tailscale uses for the tailnet. Once tailscale is up
        # it routes 100.64.0.0/10 into tailscale0, so those DNS IPs become
        # unreachable and all resolution fails. Pin public resolvers outside
        # that range instead of trusting DHCP DNS.
        DNS = ["223.5.5.5" "119.29.29.29"];
      };
      dhcpV4Config = {
        UseRoutes = false;
        UseGateway = true;
        UseDNS = false;
      };
      linkConfig = {
        RequiredForOnline = "routable";
      };
    };
  };

  services.tailscale.enable = true;

  services.nginx = {
    enable = true;
  };

  services.resolved = {
    enable = true;
    # Without a fallback resolver, tailscale/MagicDNS taking over the resolver
    # leaves no working upstream and breaks public DNS. Matches the routers.
    settings.Resolve.FallbackDNS = ["223.5.5.5"];
  };
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

  services.k3s = {
    enable = false;
    role = "agent";
    tokenFile = config.sops.secrets."k3s/token".path;
    serverAddr = "https://10.0.0.66:6443";
    extraFlags = [
      "--node-name=shanghai"
      "--node-taint=vps=true:NoSchedule"
      "--node-label=node.kubernetes.io/vps=true"
      "--node-ip=10.0.0.1"
      "--node-external-ip=10.0.0.1"
      "--flannel-iface=wg0"
    ];
  };

  services.xray.enable = true;
  # Reality private keys and the vless UUID live in sops
  # (secrets/hosts/shanghai.yaml); the config is rendered at activation.
  services.xray.settingsFile = config.sops.templates."xray-config.json".path;
  sops.templates."xray-config.json" = {
    restartUnits = ["xray.service"];
    content = builtins.toJSON {
      log.loglevel = "warning";

      reverse = {
        portals = [
          {
            tag = "portal-sh";
            domain = "reverse-sh.hank.internal";
          }
        ];
      };

      inbounds = [
        {
          tag = "interconn";
          port = 3443;
          protocol = "vless";
          settings = {
            clients = [
              {
                id = config.sops.placeholder."xray/vless_uuid";
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
              dest = "www.apple.com:443";
              serverNames = ["www.apple.com" "apple.com"];
              privateKey = config.sops.placeholder."xray/interconn_private_key";
              shortIds = ["16"];
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
                id = config.sops.placeholder."xray/vless_uuid";
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
              dest = "www.apple.com:443";
              serverNames = ["www.apple.com" "apple.com"];
              privateKey = config.sops.placeholder."xray/client_private_key";
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
          outboundTag = "portal-sh";
        }

        {
          type = "field";
          inboundTag = ["client-in"];
          outboundTag = "portal-sh";
        }
      ];
    };
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
