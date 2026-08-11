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
    # 只为了 gateway.nix —— 这台不跑 Prometheus/Grafana,只做 Grafana 的
    # 故障转移入口:http://100.64.0.13:3000 → tank,连不上自动换 h610。
    # 角色在 ./default.nix 的 roles 里("monitor-gateway"),主后端见下面的
    # my.monitoring.gateway.primary。
    ../../modules/monitoring
    ../../modules/minecraft/sh.nix
  ];

  # ---------------------------------------------------------------------
  # tailscale exit node —— 让 iOS 一个 VPN 同时拿到内网和代理。
  #
  # 起因:iOS 只允许**一个** NetworkExtension 隧道,tailscale 和代理客户端
  # 必然二选一。走 exit node 之后手机上只开 tailscale,出网流量到这台再由
  # dae 按规则分流,两样一起有。
  #
  # 链路:
  #   iOS → tailscale → 本机 tailscale0 → dae(转发流量)→ 分流
  #     → 国内直连 / 国外走 im 组 → portal → 反向隧道 → r5sjp → 出网
  #   tailnet 自身的流量不受影响 —— dae 的 routing 里 100.64.0.0/10、
  #   41641 端口、pname(tailscaled) 全是 must_direct。
  #
  # **tailscale0 必须进 lan_interface,否则整件事是空的。** dae 只代理
  # lan_interface 上的转发流量,不加的话 exit node 的流量会直接从 ens5
  # 裸奔出去 —— 结果是拿到一个上海 IP、一点分流都没有,而且这个失败是
  # 静默的(能上网,只是没走代理)。
  #
  # 只在这台覆盖:h610 和 rpi4 不是 exit node,没有 tailscale 转发流量可代理。
  # ---------------------------------------------------------------------
  my.dae.lanInterfaces = ["br-lan" "tailscale0"];

  # 广播成出口节点。useRoutingFeatures 必须显式给 —— 默认是 "none",
  # 不设的话 ip_forward 之类的内核参数不会被打开,广播了也转不动。
  #
  # 注意还有一步在机器之外:**headscale 侧要批准这条路由**。和子网路由一样,
  # 广播 ≠ 可用,`headscale nodes list-routes` 看,`headscale nodes
  # approve-routes` 批。另外 ACL 的 dst 要有 autogroup:internet(见
  # hosts/h610/system.nix 的 policy),否则策略层面就不放行出网。
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
      "k3s/token" = {};
      "acme/cloudflare_env" = {};
    }
    // lib.listToAttrs (lib.imap0 (idx: _: {
        name = "wireguard/psk/${toString idx}";
        value = {owner = "systemd-network";};
      })
      wgPeers);

  time.timeZone = "Asia/Hong_Kong";

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

      # 不做 DNS 探测,固定等待。**根因是 dae 劫持 DNS**,完整说明见 h610 的
      # security.acme 那一段(hosts/h610/system.nix)—— 两台是同一个 bug。
      #
      # 这台的具体表现:从 2026-07-31 起就没拿到过真证书,每天定时器跑一次、
      # 每次都是
      #
      #   [INFO] cloudflare: new record for sh.imdomestic.com, ID 7844f84e...
      #   propagation: time limit exceeded: last error: authoritative
      #   nameservers: NS ophelia.ns.cloudflare.com.:53 returned SERVFAIL
      #
      # TXT 记录建成功了(Cloudflare API 返回了 record ID),挂的是 lego 建完
      # 之后去权威 NS 复查那一步 —— 而那个"权威 NS"被 dae 换成了 alidns。
      #
      # 后果不只是"少一张证书":derper 会拿 NixOS 生成的自签占位证书照常启动,
      # 而节点选 home DERP 只看 **UDP 3478 的 STUN 延迟**——那个是通的。于是
      # tank/rpi4/r5s 都把这台选成了 home DERP,再连 TLS 时被拒:
      #   derper 日志 : TLS handshake error ... connection reset by peer
      #   tank 健康检查: Tailscale could not connect to the 'Shanghai' relay server
      # 也就是说一个证书坏掉的 DERP 比没有 DERP 更糟 —— 它会把节点吸过来再拒绝
      # 服务。
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
            tag = "portal-sh";
            # 这台的目录名是 shanghai,但隧道两端一直用短名 sh：r5sjp 的
            # bridge-sh 注册的是 reverse-sh.hank.internal,两边必须一字不差。
            domain = "reverse-sh.hank.internal";
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
