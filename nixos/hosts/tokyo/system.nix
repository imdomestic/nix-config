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
    # 只为了 gateway.nix —— 这台不跑 Prometheus/Grafana,只做 Grafana 的
    # 故障转移入口:http://tokyo.inner.imdomestic.com:3000 → tank,连不上自动换 h610。
    # 角色在 ./default.nix 的 roles 里("monitor-gateway"),主后端见下面的
    # my.monitoring.gateway.primary。
    ../../modules/monitoring
    ../../modules/minecraft/sh.nix
  ];

  # Host traffic is direct; Xray entries retain the Japan and Sydney reverse tunnels.
  services.tailscale.useRoutingFeatures = "server";
  services.tailscale.extraSetFlags = ["--advertise-exit-node"];

  sops.secrets =
    {
      "wireguard/private_key".owner = "systemd-network";
      # 新的一套凭据。老的三个键(vless_uuid / interconn_private_key /
      # client_private_key)已随凭据轮换从 sops 里换掉,见下面的 legacy_*。
      "xray/reality_private_key" = {};
      "xray/interconn2_uuid" = {};
      "xray/interconn2_short_id" = {};
      "xray/client_in2_uuid" = {};
      "xray/client_in2_short_id" = {};
      # 悉尼出口那条隧道的两个入口。复用本机同一对 REALITY 密钥,各自一个
      # shortId —— 和上面两个入口的做法一致。
      "xray/interconn_au_uuid" = {};
      "xray/interconn_au_short_id" = {};
      "xray/client_au_uuid" = {};
      "xray/client_au_short_id" = {};
      "k3s/token" = {};
      "acme/cloudflare_env" = {};
    }
    // lib.listToAttrs (lib.imap0 (idx: _: {
        name = "wireguard/psk/${toString idx}";
        value = {owner = "systemd-network";};
      })
      wgPeers);

  my.host.useChinaMirror = false;

  time.timeZone = "Asia/Tokyo";

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
    usePredictableInterfaceNames = false;
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

            iifname "eth0" tcp dport 27015 dnat ip to 10.0.0.66:27015
            iifname "eth0" udp dport 27015 dnat ip to 10.0.0.66:27015

            iifname "eth0" tcp dport 64738 dnat ip to 10.0.0.66:64738
            iifname "eth0" udp dport 64738 dnat ip to 10.0.0.66:64738
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
      # so WireGuard clients (10.0.0.0/24) reach the internet via the WAN (eth0).
      tables.wireguard = {
        name = "wireguard";
        enable = true;
        family = "inet";
        content = ''
          chain postrouting {
            type nat hook postrouting priority 100; policy accept;

            ip saddr 10.0.0.0/24 oifname "eth0" masquerade
          }
        '';
      };
    };
  };

  systemd.network = {
    enable = true;
    netdevs."40-wg0" = wg.netdev;
    networks."40-wg0" = wg.network;

    networks."30-eth0" = {
      matchConfig.Name = "eth0";
      # The provider's public IPv6 and gateway were observed on the bootstrap image.
      address = ["240d:c000:f06e:c600:c226:13a6:264e:3/128"];
      routes = [
        {
          Destination = "::/0";
          Gateway = "fe80::feee:ffff:feff:ffff";
          GatewayOnLink = true;
        }
      ];
      networkConfig = {
        DHCP = "yes";
        # Public DNS stays reachable when Tailscale owns 100.64.0.0/10.
        DNS = ["1.1.1.1" "8.8.8.8"];
        IPv6AcceptRA = true;
      };
      dhcpV4Config = {
        ClientIdentifier = "mac";
        UseRoutes = true;
        UseGateway = true;
        UseDNS = false;
      };
      linkConfig = {
        RequiredForOnline = "routable";
      };
    };
  };

  # Standalone DERP relay advertised by the Headscale instance on h610.
  # Client admission is checked against Headscale so this is not a public relay.
  users.groups.derper = {};
  users.users.derper = {
    isSystemUser = true;
    group = "derper";
  };

  security.acme = {
    acceptTerms = true;
    defaults.email = "hankchogan@gmail.com";
    certs."sh.imdomestic.com" = {
      dnsProvider = "cloudflare";
      environmentFile = config.sops.secrets."acme/cloudflare_env".path;
      group = "derper";
      reloadServices = ["derper.service"];

      # Keep the proven DNS-01 propagation delay; see docs/incidents.md#dae-breaks-lego-dns01.
      extraLegoFlags = ["--dns.propagation-wait" "120s"];
    };
  };

  systemd.services.derper = {
    description = "Tailscale DERP relay";
    wantedBy = ["multi-user.target"];
    wants = ["network-online.target"];
    after = [
      "network-online.target"
      "acme-sh.imdomestic.com.service"
    ];
    requires = ["acme-sh.imdomestic.com.service"];
    preStart = ''
      install -d -m 0750 /var/lib/derper/certs
      ln -sfn /var/lib/acme/sh.imdomestic.com/fullchain.pem /var/lib/derper/certs/sh.imdomestic.com.crt
      ln -sfn /var/lib/acme/sh.imdomestic.com/key.pem /var/lib/derper/certs/sh.imdomestic.com.key
    '';
    serviceConfig = {
      User = "derper";
      Group = "derper";
      StateDirectory = "derper";
      StateDirectoryMode = "0750";
      ExecStart = let
        args = [
          "-a"
          ":8443"
          "-http-port"
          "-1"
          "-stun-port"
          "3478"
          "-c"
          "/var/lib/derper/derper.key"
          "-hostname"
          "sh.imdomestic.com"
          "-certmode"
          "manual"
          "-certdir"
          "/var/lib/derper/certs"
          "-verify-client-url"
          "https://tailscale.imdomestic.com:8443/verify"
          "-verify-client-url-fail-open=false"
        ];
      in "${lib.getExe' pkgs.tailscale.derper "derper"} ${lib.escapeShellArgs args}";
      Restart = "on-failure";
      RestartSec = "5s";
      CapabilityBoundingSet = [];
      NoNewPrivileges = true;
      PrivateDevices = true;
      PrivateTmp = true;
      ProtectControlGroups = true;
      ProtectHome = true;
      ProtectKernelModules = true;
      ProtectKernelTunables = true;
      ProtectSystem = "strict";
    };
  };

  services.nginx = {
    enable = true;
  };

  # 平时把看板压在 tank 上:h610 已经背着 headscale、max、napcat、cliproxy、
  # nginx、docker,而 tank 是那台有存储、有 20 线程的机器。tank 不在了就自动
  # 换 h610 —— 这正是 2026-08-10 停电那天需要的。
  # 不写这行的话主后端会退回字母序第一台(h610),那是个没有含义的选择。
  my.monitoring.gateway.primary = "tank";

  services.resolved = {
    enable = true;
    # Without a fallback resolver, tailscale/MagicDNS taking over the resolver
    # leaves no working upstream and breaks public DNS. Matches the routers.
    settings.Resolve.FallbackDNS = ["1.1.1.1" "8.8.8.8"];
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
      "--node-name=tokyo"
      "--node-taint=vps=true:NoSchedule"
      "--node-label=node.kubernetes.io/vps=true"
      "--node-ip=10.0.0.1"
      "--node-external-ip=10.0.0.1"
      "--flannel-iface=wg0"
    ];
  };

  # Xray 的凭据全部走 sops。内联到 `settings` 会把 UUID 和 Reality 私钥同时写进
  # 这个公开仓库和 world-readable 的 nix store,所以整份 config 改由
  # sops.templates 渲染,再用 settingsFile 交给 xray。xray.service 是
  # DynamicUser + LoadCredential:systemd 先以 root 读取渲染结果,再投给动态用户,
  # 所以 root-only 的 /run/secrets/rendered 够用。
  services.xray.enable = true;
  services.xray.settingsFile = config.sops.templates."xray-config.json".path;

  sops.templates."xray-config.json" = {
    restartUnits = ["xray.service"];
    content = let
      s = config.sops.placeholder;

      # Japan DNS selects a TLS-1.2 origin; use the compatible CDN, retaining the client SNI.
      # See docs/incidents.md#tokyo-reality-cdn.
      aliyun = {
        dest = "www.aliyun.com.w.cdngslb.com:443";
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

        # 两条反向隧道,两个 portal。domain 是它们唯一的区分。
        reverse.portals = [
          {
            tag = "portal-sh";
            # 这台的目录名是 tokyo,但隧道两端一直用短名 sh：r5sjp 的
            # bridge-sh 注册的是 reverse-sh.hank.internal,两边必须一字不差。
            domain = "reverse-sh.hank.internal";
          }
          # rpi4(悉尼)。它没有公网入口,所以由它拨进来。
          {
            tag = "portal-sh-au";
            domain = "reverse-sh-au.hank.internal";
          }
        ];

        inbounds = [
          # r5sjp 的 bridge 拨进来的新落点(Step 4 切换)。
          (vlessIn "interconn2" 3444
            [(vision s."xray/interconn2_uuid")]
            (reality aliyun s."xray/reality_private_key" s."xray/interconn2_short_id"))

          # 自己用的新入口,凭据与老的完全无关。
          (vlessIn "client-in2" 54322
            [(vision s."xray/client_in2_uuid")]
            (reality aliyun s."xray/reality_private_key" s."xray/client_in2_short_id"))

          # ↓ 悉尼出口。端口取 +1 / +2,和上面日本那套错开。
          # rpi4 的 bridge 拨进来的落点。
          (vlessIn "interconn-au" 3445
            [(vision s."xray/interconn_au_uuid")]
            (reality aliyun s."xray/reality_private_key" s."xray/interconn_au_short_id"))

          # 自己用:想从悉尼出网时连这个口。
          (vlessIn "client-au" 54324
            [(vision s."xray/client_au_uuid")]
            (reality aliyun s."xray/reality_private_key" s."xray/client_au_short_id"))
        ];

        outbounds = [
          {
            tag = "direct";
            protocol = "freedom";
          }
        ];

        # 入口决定出口:前两个进日本那条隧道,后两个进悉尼那条。
        #
        # 每条规则都必须同时收下 interconn-* 和 client-*:前者是 bridge 拨进来
        # 的控制信道(目的地正是 portal 的内部域名),后者是真正的用户流量。
        routing.rules = [
          {
            type = "field";
            inboundTag = ["interconn2" "client-in2"];
            outboundTag = "portal-sh";
          }
          {
            type = "field";
            inboundTag = ["interconn-au" "client-au"];
            outboundTag = "portal-sh-au";
          }
        ];
      };
  };

  security.sudo.wheelNeedsPassword = false;

  # fzf 删了:home/profiles/interactive.nix 里的 programs.fzf 已经装了它。
  # git 和 neovim 留着 —— 这是台服务器,出事时是 root 进来修,而且本机
  # `nixos-rebuild --flake` 要 git。
  environment.systemPackages = with pkgs; [
    git
    neovim
  ];
  environment.pathsToLink = ["/share/applications" "/share/xdg-desktop-portal"];

  programs.zsh.enable = true;
  system.stateVersion = "26.05";
}
