{
  pkgs,
  pkgs-unstable,
  inputs,
  config,
  lib,
  ...
}: let
  matrixUpstream = "http://100.64.0.4:8008";
  wg = import ../../../lib/wgClient.nix {inherit pkgs;} {
    privateKeyFile = config.sops.secrets."wireguard/private_key".path;
    presharedKeyFile = config.sops.secrets."wireguard/preshared_key".path;
    address = "10.0.0.5/24";
  };
in {
  imports = [
    ../../modules/airport
    ../../modules/dae
    ../../modules/keyd
    ../../modules/qq-deepseek-bot
    # ../../modules/minecraft/wuxi.nix
  ];

  sops.secrets."wireguard/private_key".owner = "systemd-network";
  sops.secrets."wireguard/preshared_key".owner = "systemd-network";

  # Service secrets (were hand-placed under /var/lib/secrets).
  # acme (root, via systemd EnvironmentFile) and livekit/lk-jwt (LoadCredential)
  # read as root, so root-owned is enough. coturn is different: its
  # static-auth-secret-file is consumed by a `replace-secret` ExecStartPre that
  # runs as the turnserver user, so that secret must be owned by turnserver.
  sops.secrets."acme/cloudflare_env" = {};
  sops.secrets."coturn/static_auth_secret".owner = "turnserver";
  sops.secrets."livekit/keys_yaml" = {};

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.kernelPackages = pkgs.linuxPackages_latest;

  # This host is the deploy-rs build box; emulate aarch64 so it can build the
  # SBC (r6s/rpi4/r5s) closures locally before pushing them.
  boot.binfmt.emulatedSystems = ["aarch64-linux"];
  # boot.kernelParams = [
  #   "pcie_aspm=off"
  #   "i915.force_probe=!56a5"
  #   "xe.force_probe=56a5"
  #   "enable_guc=3"
  # ];
  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
    "net.core.default_qdisc" = "fq";
    "net.ipv4.tcp_congestion_control" = "bbr";
  };

  time.timeZone = "Asia/Hong_Kong";

  networking = {
    networkmanager.enable = false; # Easiest to use and most distros use this by default.
    useDHCP = false;
    useNetworkd = true;
    nftables = {
      enable = true;
      tables.router = {
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
      trustedInterfaces = ["br-lan"];
      interfaces."ppp0".allowedUDPPorts = [546];
      checkReversePath = false;
    };
  };

  services.pppd = {
    enable = true;
    peers = {
      telecom = {
        autostart = true;
        enable = true;
        config = ''
          plugin pppoe.so eno1
          user "051012664304"
          password "845747"

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

          mtu 1492
          mru 1492
        '';
      };
    };
  };

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

    # LAN
    networks."20-lan-uplink" = {
      matchConfig.Name = "enp5s0";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    networks."20-wan-uplink" = {
      matchConfig.Name = "eno1";
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
        Address = "10.0.1.1/24";
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
        DNS = ["10.0.1.1"];
      };

      # SLAAC
      ipv6SendRAConfig = {
        Managed = false; # no DHCPv6
        OtherInformation = false;
        EmitDNS = true; # send DNS with RA
      };
    };
  };

  systemd.tmpfiles.rules = [
    "d /var/lib/coturn 0750 root turnserver -"
  ];

  services.dnsmasq.enable = false;
  services.resolved = {
    enable = true;
    settings.Resolve = {
      FallbackDNS = ["223.5.5.5"];
      DNSStubListener = "yes";
      DNSStubListenerExtra = ["10.0.1.1" "::"];
    };
  };

  security.acme = {
    acceptTerms = true;
    defaults.email = "hankchogan@gmail.com";
  };

  security.acme.certs."tailscale.imdomestic.com" = {
    dnsProvider = "cloudflare";
    environmentFile = config.sops.secrets."acme/cloudflare_env".path;
    group = "nginx";
  };

  security.acme.certs."matrix.imdomestic.com" = {
    dnsProvider = "cloudflare";
    environmentFile = config.sops.secrets."acme/cloudflare_env".path;
    group = "nginx";
  };

  security.acme.certs."rtc.imdomestic.com" = {
    dnsProvider = "cloudflare";
    environmentFile = config.sops.secrets."acme/cloudflare_env".path;
    group = "nginx";
    reloadServices = [
      "nginx.service"
      "coturn.service"
    ];
  };

  security.acme.certs."max.imdomestic.com" = {
    dnsProvider = "cloudflare";
    environmentFile = config.sops.secrets."acme/cloudflare_env".path;
    group = "nginx";
  };

  # ddns-go cloudflare token + web password rendered from sops.
  sops.secrets."ddns/cloudflare_token" = {};
  sops.secrets."ddns/web_password" = {};
  sops.templates."ddns-go-config.yaml" = {
    restartUnits = ["ddns-go.service"];
    content = ''
      dnsconf:
          - name: "h610"
            ipv4:
              enable: true
              gettype: netInterface
              url: https://myip.ipip.net, https://ddns.oray.com/checkip, https://ip.3322.net, https://4.ipw.cn, https://v4.yinghualuo.cn/bejson
              netinterface: ppp0
              cmd: ""
              domains:
                  - h610:imdomestic.com
                  - tailscale:imdomestic.com
                  - matrix:imdomestic.com
                  - rtc:imdomestic.com
                  - max:imdomestic.com
            ipv6:
              enable: true
              gettype: netInterface
              url: https://speed.neu6.edu.cn/getIP.php, https://v6.ident.me, https://6.ipw.cn, https://v6.yinghualuo.cn/bejson
              netinterface: ppp0
              cmd: ""
              ipv6reg: ""
              domains:
                  - matrix:imdomestic.com
                  - rtc:imdomestic.com
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
  # 订阅服务要把这两个值写进给客户端的配置里,所以 airport 用户得读得到。
  sops.secrets."xray/friends_short_id".owner = "airport";
  sops.secrets."xray/reality_public_key".owner = "airport";

  services.xray.enable = true;
  services.xray.settingsFile = config.sops.templates."xray-config.json".path;

  sops.templates."xray-config.json" = {
    restartUnits = ["xray.service"];
    content = let
      s = config.sops.placeholder;

      # 三个新入口共用 h610 这台的新密钥对,各自一个 shortId。
      # 新入口换 aliyun:www.apple.com 是全网最被滥用的 SNI(xray 为此告警),
      # 而 www.aliyun.com 证书记录 2845B、解析到江苏电信段、dest 拨号不出省。
      reality = shortId: {
        network = "tcp";
        security = "reality";
        realitySettings = {
          show = false;
          dest = "www.aliyun.com:443";
          serverNames = ["www.aliyun.com"];
          privateKey = s."xray/reality_private_key";
          shortIds = [shortId];
        };
      };

      # 老密钥对。私钥和 UUID 都已随公开仓库泄露,只为过渡期保活,Step 5 删。
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

        # 每用户流量计数 + 运行时增删用户,airport 控制器靠这两个接口干活。
        # 只有带 email 的 client 才会产生 user>>> 计数,所以 client-in2 和
        # interconn2 那些不带 email 的连接不会被统计。
        stats = {};
        api = {
          tag = "api";
          listen = "127.0.0.1:10085";
          services = ["StatsService" "HandlerService"];
        };
        policy = {
          levels."0" = {
            statsUserUplink = true;
            statsUserDownlink = true;
          };
          system = {
            statsInboundUplink = true;
            statsInboundDownlink = true;
          };
        };

        reverse.portals = [
          {
            tag = "portal-h610";
            domain = "reverse-h610.hank.internal";
          }
        ];

        inbounds = [
          # r5sjp 的 bridge 拨进来的新落点(Step 4 切换)。
          (vlessIn "interconn2" 1444
            [(vision s."xray/interconn2_uuid")]
            (reality s."xray/interconn2_short_id"))

          # 自己用:dae 的 im 组换到这里(Step 2)。不带 email,不计量不限额。
          (vlessIn "client-in2" 54322
            [(vision s."xray/client_in2_uuid")]
            (reality s."xray/client_in2_short_id"))

          # 朋友专用。clients 故意留空,由 airport 控制器在运行时用
          # `xray api adu` 注入(Step 6),这样 UUID 既不进 git 也不进 nix store。
          (vlessIn "friends-in" 54323 [] (reality s."xray/friends_short_id"))
        ];

        outbounds = [
          {
            tag = "direct";
            protocol = "freedom";
          }
        ];

        # 五个入口一律丢进反向隧道,从 r5sjp 的日本出口出去。
        routing.rules = [
          {
            type = "field";
            inboundTag = ["interconn2" "client-in2" "friends-in"];
            outboundTag = "portal-h610";
          }
        ];
      };
  };

  # 朋友的订阅服务。UUID 和订阅 token 由控制器在运行时签发,存在
  # /var/lib/airport,所以这里只声明配额和到期,加人不用碰 sops。
  services.airport = {
    enable = true;
    server = {
      address = "h610.imdomestic.com";
      port = 54323;
      name = "imdomestic-jp";
      publicKeyFile = config.sops.secrets."xray/reality_public_key".path;
      shortIdFile = config.sops.secrets."xray/friends_short_id".path;
    };
    # 电信把 80/443 入站掐了,所以订阅和 headscale 一起挂在 8443,靠 SNI 分流。
    subscription.baseUrl = "https://h610.imdomestic.com:8443";

    users = {
      # 示例,按需增删。quotaGB 是上下行合计,用完为止不自动重置;
      # 想续期就改数字重新部署,或者跑 `airport reset <用户>`。
      # alice = {
      #   quotaGB = 100;
      #   expires = "2026-12-31";
      # };
      test = {
        quotaGB = 100;
        expires = "2026-08-31";
      };

      bordersaki = {
        quotaGB = 200;
        expires = "2026-09-30";
      };
    };
  };

  # 订阅走已有的 8443,证书用现成的 Cloudflare DNS-01 签。h610.imdomestic.com
  # 本来就由 ddns-go 在更新,所以不用额外加 DNS 记录。
  security.acme.certs."h610.imdomestic.com" = {
    dnsProvider = "cloudflare";
    environmentFile = config.sops.secrets."acme/cloudflare_env".path;
    group = "nginx";
  };

  services.displayManager.gdm.enable = false;
  services.desktopManager.gnome.enable = false;

  services.cockpit.enable = lib.mkForce false;

  services.ollama = {
    enable = true;
    package = pkgs-unstable.ollama-vulkan;
  };

  users.users.turnserver.extraGroups = ["nginx"];

  programs.zsh = {
    enable = true;
  };

  programs.nix-ld.enable = true;

  xdg.portal.wlr.enable = true;

  hardware.enableRedistributableFirmware = true;
  hardware.graphics = {
    enable = true;
    extraPackages = with pkgs; [
      vpl-gpu-rt
      intel-compute-runtime
      intel-media-driver
      mesa
    ];
    enable32Bit = true;
  };
  # max-bot membership lets hank edit the config/env files under /var/lib/max-bot
  users.users.hank.extraGroups = ["video" "render" "docker" "max-bot"];

  # max bot: the Haskell code shells out to the real docker CLI and the
  # napcat compose file relies on host-gateway, so use Docker here rather
  # than the podman/dockerCompat setup other hosts use.
  virtualisation.docker.enable = true;
  # The host resolv.conf points at the systemd-resolved stub, so docker
  # falls back to 8.8.8.8 — which resolves CN sites to overseas CDNs that
  # don't load from here. Pin domestic resolvers for containers instead.
  virtualisation.docker.daemon.settings.dns = ["223.5.5.5" "119.29.29.29"];

  # max QQ bot (module from the max flake). The yaml is full of LLM API
  # keys, so it lives on disk under /var/lib/max-bot rather than in
  # `settings` (world-readable store).
  # 管理面板的开关走环境变量而不是 services.max.settings:这台机器用的是
  # 手工管理的 configFile,settings 会被整个忽略(module 自己会 warn)。
  # env 在 opt-env-conf 里压过文件,所以这两行无论 max.yaml 怎么写都生效。
  #
  # 只绑回环:公网入口是 nginx 那个 max.imdomestic.com vhost,面板自己
  # 不该直接对外。MAX_ADMIN_TOKEN 放在 max-bot.env 里(不要写进 nix,
  # 会进 world-readable 的 nix store)。
  systemd.services.max.environment = {
    MAX_ADMIN_HOST = "127.0.0.1";
    MAX_ADMIN_PORT = "7700";
  };

  services.max = {
    enable = true;
    configFile = "/var/lib/max-bot/max.yaml";
    environmentFile = "/var/lib/max-bot/max-bot.env"; # MAX_ACCESS_TOKEN, MAX_ADMIN_TOKEN
    napcat = {
      enable = true;
      qq = "2107570581";
      environmentFiles = ["/var/lib/max-bot/napcat.env"]; # NAPCAT_ACCESS_TOKEN
    };
    wechatpad = {
      enable = false;
      adminKey = "hbhbhb";
      webBindAddress = "100.64.0.3";
    };
  };
  # headscale owns 127.0.0.1:8080, so bind the OneBot WS on the docker
  # bridge only; napcat reaches it via host.docker.internal (host-gateway).
  systemd.services.max.environment = {
    MAX_WS_HOST = "172.17.0.1";
    MAX_LOG_COLOR = "always";
  };

  services.qq-deepseek-bot = {
    enable = true;
    sourceDirectory = "/home/kenneth/services/chat-bot";
    environmentFile = "/home/kenneth/services/chat-bot/.env";
    user = "kenneth";
    group = "users";
    host = "172.17.0.1";
    port = 18080;
    sandbox.enable = false;
    napcat = {
      enable = true;
      account = "3580515978";
      webuiPort = 6100;
    };
  };

  environment = {
    variables = {
      EDITOR = "nvim";
    };
  };

  environment.systemPackages = with pkgs; [
    gcc
    neovim
    nginx
    intel-gpu-tools
    deploy-rs
    docker-compose
  ];

  environment.sessionVariables = {
    LIBVA_DRIVER_NAME = "iHD";
    NIXOS_OZONE_WL = "1";
  };
  xdg.portal.config.common.default = "*";

  services.openssh.enable = true;
  services.tailscale.enable = true;

  services.headscale = {
    enable = true;
    address = "127.0.0.1";
    port = 8080;
    settings = {
      policy.path = "${pkgs.writeText "headscale-policy.json" (builtins.toJSON {
        groups = {
          "group:imdomestic" = [
            "hank@imdomestic.com"
            "linwhite@imdomestic.com"
            "fendada@imdomestic.com"
            "kenneth@imdomestic.com"
          ];
        };

        acls = [
          # 核心规则：允许这个组内的所有人访问该组内的所有设备（所有端口）
          {
            action = "accept";
            src = ["group:imdomestic"];
            dst = ["group:imdomestic:*"];
          }

          # (可选) 允许所有人访问你广播的特定子网（比如你家的 R6S 局域网）
          # {
          #   action = "accept";
          #   src = [ "group:friends" ];
          #   dst = [ "192.168.1.0/24:*" ];
          # }
        ];
      })}";
      server_url = "https://tailscale.imdomestic.com:8443";
      derp.server = {
        enabled = true;
        region_id = 610;
        region_code = "h610";
        region_name = "H610";
        stun_listen_addr = "0.0.0.0:3479";
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

  # services.headplane = {
  #   enable = true;
  #   debug = true;
  #   settings = {
  #     server = {
  #       host = "127.0.0.1";
  #       port = 3000;
  #       base_url = "https://tailscale.imdomestic.com:8443";
  #       cookie_secure = true;
  #       cookie_secret_path = "/var/lib/secrets/headplane/cookie_secret";
  #     };
  #     headscale = {
  #       url = "http://127.0.0.1:8080";
  #       public_url = "https://tailscale.imdomestic.com:8443";
  #     };
  #     integration = {
  #       agent = {
  #         enabled = false;
  #         pre_authkey_path = "/var/lib/secrets/headplane/agent_preauthkey";
  #       };
  #       proc.enabled = true;
  #     };
  #   };
  # };

  services.coturn = {
    enable = true;
    no-cli = true;
    use-auth-secret = true;
    static-auth-secret-file = config.sops.secrets."coturn/static_auth_secret".path;
    realm = "rtc.imdomestic.com";
    cert = "/var/lib/acme/rtc.imdomestic.com/fullchain.pem";
    pkey = "/var/lib/acme/rtc.imdomestic.com/key.pem";
    listening-port = 3478;
    alt-listening-port = 3480;
    tls-listening-port = 5349;
    alt-tls-listening-port = 5351;
    min-port = 49152;
    max-port = 49999;
  };

  services.livekit = {
    enable = true;
    keyFile = config.sops.secrets."livekit/keys_yaml".path;
    settings = {
      port = 7880;
      room.auto_create = false;
      rtc = {
        tcp_port = 7881;
        port_range_start = 50000;
        port_range_end = 51000;
        use_external_ip = true;
      };
    };
  };

  services.lk-jwt-service = {
    enable = true;
    keyFile = config.sops.secrets."livekit/keys_yaml".path;
    port = 8088;
    livekitUrl = "wss://rtc.imdomestic.com:8448/livekit/sfu";
  };

  systemd.services.lk-jwt-service = {
    wants = ["livekit.service"];
    after = ["livekit.service"];
    environment.LIVEKIT_FULL_ACCESS_HOMESERVERS = "imdomestic.com";
  };

  services.nginx = {
    enable = true;
    clientMaxBodySize = "50m";
    # 订阅端点唯一的认证就是路径里那段 token,所以给它一个限速桶,
    # 别让人拿这个公网端口慢慢撞。
    appendHttpConfig = ''
      limit_req_zone $binary_remote_addr zone=airportsub:1m rate=10r/m;
      # max 管理面板的唯一凭据是一个 bearer token,而它挂在公网上,
      # 所以给 /api/ 一个桶:正常用起来一次翻页也就几个请求,
      # 但撞 token 需要的量级远在这之上。
      limit_req_zone $binary_remote_addr zone=maxapi:1m rate=60r/m;
    '';
  };

  # 订阅端点。和 headscale 共用 8443,靠 SNI 分流。
  services.nginx.virtualHosts."h610.imdomestic.com" = {
    serverName = "h610.imdomestic.com";
    useACMEHost = "h610.imdomestic.com";
    forceSSL = true;
    http2 = true;
    listen = [
      {
        addr = "0.0.0.0";
        port = 8443;
        ssl = true;
      }
      {
        addr = "[::]";
        port = 8443;
        ssl = true;
      }
    ];
    # 只开 /sub/,其余一律 404,不暴露这台机器上还有别的东西。
    locations."/sub/" = {
      proxyPass = "http://127.0.0.1:8081";
      extraConfig = ''
        limit_req zone=airportsub burst=5 nodelay;
        proxy_set_header Host $host;
        # 订阅客户端靠这个响应头显示已用/总量/到期,别被过滤掉
        proxy_pass_header Subscription-Userinfo;
      '';
    };
    locations."/" = {
      extraConfig = "return 404;";
    };
  };

  # max 管理面板。和别的一样挂 8443(电信封了 443),SNI 分流。
  #
  # 面板本身跑在 bot 进程里,只绑 127.0.0.1,所以进出这台机器的唯一
  # 通道就是这个 vhost。它自己不做 TLS、没有用户体系,认证只有一个
  # bearer token —— token 在 /var/lib/max-bot/max-bot.env 里设
  # MAX_ADMIN_TOKEN,别写进 max.yaml。
  #
  # 静态资源(HTML/JS/CSS)是不需要 token 的:<script> 标签带不了
  # Authorization 头。它们不含任何数据,所有状态都要过 /api/,而
  # /api/ 每一条都验 token。
  services.nginx.virtualHosts."max.imdomestic.com" = {
    serverName = "max.imdomestic.com";
    useACMEHost = "max.imdomestic.com";
    forceSSL = true;
    http2 = true;
    listen = [
      {
        addr = "0.0.0.0";
        port = 8443;
        ssl = true;
      }
      {
        addr = "[::]";
        port = 8443;
        ssl = true;
      }
    ];
    locations."/" = {
      proxyPass = "http://127.0.0.1:7700";
      extraConfig = ''
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
      '';
    };
    # 数据面单独限速。burst 给到 20 是因为切一次标签页会并发拉
    # overview + 列表 + 两张图,一次操作打出小几个请求很正常。
    locations."/api/" = {
      proxyPass = "http://127.0.0.1:7700";
      extraConfig = ''
        limit_req zone=maxapi burst=20 nodelay;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
      '';
    };
  };

  services.nginx.virtualHosts."tailscale.imdomestic.com" = {
    serverName = "tailscale.imdomestic.com";
    useACMEHost = "tailscale.imdomestic.com";
    forceSSL = true;
    http2 = true;
    listen = [
      {
        addr = "0.0.0.0";
        port = 8443;
        ssl = true;
      }
      {
        addr = "[::]";
        port = 8443;
        ssl = true;
      }
    ];
    locations."/" = {
      proxyPass = "http://127.0.0.1:8080";
      proxyWebsockets = true;
      extraConfig = ''
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
      '';
    };
    # locations."= /admin" = {
    #   extraConfig = ''
    #     return 302 /admin/;
    #   '';
    # };
    # locations."/admin/" = {
    #   proxyPass = "http://127.0.0.1:3000";
    #   proxyWebsockets = true;
    #   extraConfig = ''
    #     proxy_set_header Host $host;
    #     proxy_set_header X-Real-IP $remote_addr;
    #     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    #     proxy_set_header X-Forwarded-Proto $scheme;
    #     proxy_read_timeout 3600s;
    #     proxy_send_timeout 3600s;
    #   '';
    # };
  };
  services.nginx.virtualHosts."matrix.imdomestic.com" = {
    serverName = "matrix.imdomestic.com";
    useACMEHost = "matrix.imdomestic.com";
    addSSL = true;
    http2 = true;
    listen = [
      {
        addr = "0.0.0.0";
        port = 8448;
        ssl = true;
      }
      {
        addr = "[::]";
        port = 8448;
        ssl = true;
      }
    ];

    locations."/" = {
      proxyPass = matrixUpstream;
      proxyWebsockets = true;
      extraConfig = ''
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
      '';
    };
  };
  services.nginx.virtualHosts."rtc.imdomestic.com" = {
    serverName = "rtc.imdomestic.com";
    useACMEHost = "rtc.imdomestic.com";
    addSSL = true;
    http2 = true;
    listen = [
      {
        addr = "0.0.0.0";
        port = 8448;
        ssl = true;
      }
      {
        addr = "[::]";
        port = 8448;
        ssl = true;
      }
    ];

    locations."= /livekit/jwt" = {
      return = "308 /livekit/jwt/";
    };

    locations."/livekit/jwt/" = {
      proxyPass = "http://127.0.0.1:8088/";
      extraConfig = ''
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
      '';
    };

    locations."= /livekit/sfu" = {
      return = "308 /livekit/sfu/";
    };

    locations."/livekit/sfu/" = {
      proxyPass = "http://127.0.0.1:7880/";
      proxyWebsockets = true;
      extraConfig = ''
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
      '';
    };

    locations."/" = {
      return = "404";
    };
  };

  # Passwordless deploy from this box (it rebuilds itself, often driven
  # by an agent without a tty).  nixos-rebuild/nh only ever sudo three
  # things: `nix-env --set` on the system profile, the systemd-run
  # wrapper, and the generation's switch-to-configuration.  Deliberately
  # narrower than a blanket wheel NOPASSWD, though not a hard privilege
  # boundary — treat it as convenience, not containment.
  security.sudo.extraRules = lib.mkAfter [
    {
      users = ["hank"];
      commands = [
        {
          command = "/run/current-system/sw/bin/nix-env";
          options = ["NOPASSWD"];
        }
        {
          command = "/run/current-system/sw/bin/systemd-run";
          options = ["NOPASSWD"];
        }
        {
          command = "/nix/store/*/bin/switch-to-configuration";
          options = ["NOPASSWD"];
        }
      ];
    }
  ];

  system.stateVersion = "25.11";
}
