{
  pkgs,
  pkgs-unstable,
  inputs,
  config,
  lib,
  ...
}: let
  matrixUpstream = "http://100.64.0.4:8008";
  mkCliProxyProfile = model: aliases: {
    provider = "cliproxy";
    protocol = "openai-chat";
    base_url = "http://100.64.0.3:8317/v1";
    api_key_env = "CLIPROXY_API_KEY";
    inherit model aliases;
    timeout_seconds = 180;
    thinking = "auto";
    capabilities = {
      tools = true;
      streaming = true;
      json_mode = true;
      vision = false;
    };
  };
  qqBotModelProfiles = builtins.toJSON {
    default = "deepseek";
    profiles = {
      deepseek = {
        provider = "deepseek";
        protocol = "openai-chat";
        base_url = "https://api.deepseek.com";
        api_key_env = "DEEPSEEK_API_KEY";
        model = "deepseek-v4-flash";
        thinking = "disabled";
        aliases = ["default" "ds" "flash"];
      };
      "deepseek-pro" = {
        provider = "deepseek";
        protocol = "openai-chat";
        base_url = "https://api.deepseek.com";
        api_key_env = "DEEPSEEK_API_KEY";
        model = "deepseek-v4-pro";
        thinking = "disabled";
        aliases = ["pro"];
      };
      "gpt-5.3-codex-spark" = mkCliProxyProfile "gpt-5.3-codex-spark" ["spark"];
      "gpt-5.4" = mkCliProxyProfile "gpt-5.4" ["gpt" "gpt54"];
      "gpt-5.4-mini" = mkCliProxyProfile "gpt-5.4-mini" ["mini" "gpt54mini"];
      "gpt-5.5" = mkCliProxyProfile "gpt-5.5" ["gpt55"];
      "gpt-5.6-terra" = mkCliProxyProfile "gpt-5.6-terra" ["terra"];
      "gpt-5.6-luna" = mkCliProxyProfile "gpt-5.6-luna" ["luna"];
      "gpt-5.6-sol" = mkCliProxyProfile "gpt-5.6-sol" ["sol"];
      "codex-auto-review" = mkCliProxyProfile "codex-auto-review" ["review"];
    };
  };
  # Headscale decodes regions as map[int]*DERPRegion. Nix attrset keys are
  # strings, and pkgs.formats.yaml therefore quotes 611, which yaml.v3 rejects.
  headscaleDerpMap = pkgs.writeText "headscale-derp-map.yaml" ''
    regions:
      611:
        regionid: 611
        regioncode: shanghai
        regionname: Shanghai
        nodes:
          - name: 611a
            regionid: 611
            hostname: sh.imdomestic.com
            ipv4: 101.132.183.117
            ipv6: none
            derpport: 8443
            stunport: 3478
  '';
  wg = import ../../../lib/wgClient.nix {inherit pkgs;} {
    privateKeyFile = config.sops.secrets."wireguard/private_key".path;
    presharedKeyFile = config.sops.secrets."wireguard/preshared_key".path;
    address = "10.0.0.5/24";
  };
in {
  imports = [
    ../../modules/airport
    ../../modules/cliproxy
    # 2026-07-31 试过 mihomo,因为 cliproxy 一直 EOF 而回滚,见
    # docs/proxy-todo.md 第 9 节。r6s 上同一份配置是好的,所以问题多半出在
    # 这台的链路质量(五条里最差)上,而不是配置本身。下面 my.mihomo.* 那几行
    # 留着,重新试的时候把这两行换回来即可。
    ../../modules/dae
    # ../../modules/mihomo
    ../../modules/keyd
    ../../modules/qq-bot-postgres-ha.nix
    # 监控的第二份(tank 是第一份)。开关读 ./default.nix 的 roles,不在这里写。
    #   Prometheus    http://100.64.0.3:9009
    #   Alertmanager  http://100.64.0.3:9093
    #   Grafana       http://100.64.0.3:3000
    ../../modules/monitoring
    # ../../modules/minecraft/wuxi.nix
  ];

  sops.secrets."wireguard/private_key".owner = "systemd-network";
  sops.secrets."wireguard/preshared_key".owner = "systemd-network";

  # 把 ChatGPT 订阅包成 OpenAI 兼容 API。只绑 tailscale 地址 —— 见模块里
  # bindAddress 的说明,公网上不该有这个监听。
  services.cliproxy = {
    enable = true;
    bindAddress = "100.64.0.3";
  };

  # 重新启用 modules/mihomo 时这几行就位,现在 import 注释掉了所以是死设置
  # (选项由该模块定义,模块不 import 时这些赋值会导致求值失败,所以一并注释)。
  #   my.mihomo.router = true;            # 这台是网关(br-lan 10.0.1.1/24)
  #   my.mihomo.smart = true;
  #   my.mihomo.controllerAddress = "100.64.0.3:9090";   # 面板,只绑 tailscale

  # Service secrets (were hand-placed under /var/lib/secrets).
  # acme (root, via systemd EnvironmentFile) and livekit/lk-jwt (LoadCredential)
  # read as root, so root-owned is enough. coturn is different: its
  # static-auth-secret-file is consumed by a `replace-secret` ExecStartPre that
  # runs as the turnserver user, so that secret must be owned by turnserver.
  sops.secrets."acme/cloudflare_env" = {};
  sops.secrets."coturn/static_auth_secret".owner = "turnserver";
  sops.secrets."livekit/keys_yaml" = {};
  sops.secrets."qq_bot/postgres_password" = {
    sopsFile = ../../../secrets/secrets.yaml;
    owner = "postgres";
    group = "postgres";
    mode = "0400";
    restartUnits = ["qq-bot-postgres-bootstrap.service"];
  };
  sops.secrets."qq_bot/ha_password" = {
    sopsFile = ../../../secrets/secrets.yaml;
    owner = "postgres";
    group = "postgres";
    mode = "0400";
    restartUnits = [
      "qq-bot-postgres-monitor.service"
      "qq-bot-postgres-node.service"
      "qq-bot-postgres-bootstrap.service"
    ];
  };

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.kernelPackages = pkgs.linuxPackages_latest;

  # **故意不开 binfmt。** 这台以前是 deploy-rs 的构建机,靠 QEMU 模拟给
  # r6s/rpi4/r5s 那几台 SBC 编闭包;那个角色已经交给 tank 了
  # (见 modules/nix.nix 的 buildMachines)。
  #
  # 摘掉的理由是**溢出**,不是"抢在 tank 前面"。nix 的调度是远程优先:
  # derivation-building-goal.cc 先问 build hook,hook 在 tank 有空闲 slot
  # 时就 accept,所以 ARM 构建本来就会去 tank。
  #
  # 但 binfmt 会把 aarch64-linux 加进 `extra-platforms`,于是 build-remote.cc
  # 里的 `couldBuildLocally` 为真;一旦 tank 的 16 个 slot 全占满,hook 返回
  # decline 而不是 postpone —— 溢出的 ARM 构建就落到这台 12 核 / 15 GiB 的
  # 机器上用 QEMU 跑。那是最坏的组合,而这台今天已经 OOM 两次。
  #
  # 摘掉之后那种情况变成 postpone(排队等 tank),不再有慢速回落。
  # 代价:tank 不可达时这台编不了 ARM(直接失败而不是慢慢磨),
  # `just build-local <arm-host>` 在这台上也不再可用 —— 那条路本来就
  # 慢到没有实用价值。
  # boot.binfmt.emulatedSystems = ["aarch64-linux"];
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

    # --- 内存压力 (见下面 zramSwap / systemd.oomd) ---
    #
    # zram 的 swap 是内存里的压缩块,不是磁盘,读写快两三个数量级。默认的
    # swappiness=60 是按"换出去很贵"调的,对 zram 太保守 —— 结果是内核宁可
    # 反复丢弃并重读页缓存(可执行页、库)也不肯换出匿名页,那正是机器看起来
    # 卡死的样子。150 让它优先压缩匿名页。
    "vm.swappiness" = 150;

    # 换入时的预读页数,2^N。磁盘上顺序预读是赚的,zram 上不是:解压本身
    # 就是成本,预读进来用不上的页纯浪费 CPU。0 = 一次只换入一页。
    "vm.page-cluster" = 0;

    # 让内核更早开始后台回收,而不是等到水位线才同步回收。125 是 zram
    # 场景的常见值,代价是平时多一点点回收开销。
    "vm.watermark_scale_factor" = 125;
  };

  # 这台是 15 GiB 内存 + **没有任何 swap**。没有 swap 时内核没地方腾挪匿名页,
  # 内存吃紧就只能反复回收页缓存,机器进入长时间无响应但也没被 OOM 杀掉的
  # 状态 —— `nix flake check` 这种一次求值 23 台配置的活很容易触发。
  #
  # zram 给内核一个去处,而且是压缩后放在内存里(典型 2-3:1),所以 8 GiB 的
  # zram 大致能吃下 16-24 GiB 匿名页。它把"硬卡死"变成"变慢"。
  #
  # 不用磁盘 swap:这台是 SSD,写放大不划算,而且真换到磁盘上照样卡。
  zramSwap = {
    enable = true;
    # 15.4 GiB 的一半。再高会挤占本来能放页缓存的物理内存,反而更差。
    memoryPercent = 50;
    algorithm = "zstd";
  };

  # oomd 本来就是开的(NixOS 默认 systemd.oomd.enable = true),但三个 slice
  # 开关默认全是 false,所以它跑着却一个 cgroup 都没在看 —— `oomctl` 里
  # "Swap Monitored CGroups" 和 "Memory Pressure Monitored CGroups" 都是空的。
  # 这就是上次内存打满时它什么也没做的原因。
  systemd.oomd = {
    # 交互式的活(登录会话、终端里跑的 nix eval/build)都在 user slice 里,
    # 上次卡死的就是这一类。开它。
    enableUserSlices = true;

    # **故意不开 enableSystemSlice。** 这台的 system.slice 里是 headscale、
    # max、napcat、cliproxy、nginx、docker —— 让 oomd 在整个 system.slice 上
    # 按压力挑一个杀,挑中的很可能是 matrix 转发或者 bot,那是拿服务中断换
    # 内存。nix 构建的内存单独在下面用 MemoryHigh 限,比无差别杀精确得多。
    #
    # 同理不开 enableRootSlice(它是 system.slice 的父级,范围只会更大)。

    settings.OOM = {
      # 默认 60%/30s。压到 80%/20s:这台跑着 fleet 的关键服务,宁可让
      # 内存压力持续久一点也别误杀;但真到 80% 持续 20 秒,那就是回不来了,
      # 早杀早解脱。
      DefaultMemoryPressureLimit = "80%";
      DefaultMemoryPressureDurationSec = "20s";
    };
  };

  # nixpkgs 的 oomd 模块把上面那几行写进 /etc/systemd/oomd.conf,但**没有**把它
  # 挂进 systemd-oomd 的重启触发链。NixOS 的 switch 只重启"unit 定义变了"的
  # 服务,而 oomd.conf 是 /etc 里的普通文件不算 unit 定义 —— 结果是配置换了、
  # 文件也写对了,进程却还跑着旧的那份。
  #
  # 实测就踩了:switch 之后 `oomctl` 顶部仍然显示 60%/30s(systemd 内建默认),
  # 而不是这里写的 80%/20s。每个 cgroup 自己那条 80% 是生效的(它来自 slice
  # unit,那个确实会触发重启),只有全局默认是陈的,很容易看漏。
  systemd.services.systemd-oomd.restartTriggers = [
    config.environment.etc."systemd/oomd.conf".source
  ];

  # nix 构建跑在 nix-daemon 里(system.slice),上面刻意没让 oomd 管那一片,
  # 所以在这里单独给它一个上限。
  #
  # 用 MemoryHigh 不用 MemoryMax:High 是软限,超了内核给这个 cgroup 加回收
  # 压力让它变慢,而 Max 是硬限,超了直接杀 —— 构建跑到一半被杀掉只会浪费
  # 前面所有的编译。这台 12 核,max-jobs 默认 auto 就是 12 个并行构建,
  # 10G 差不多是"能同时开满但别把机器拖垮"的位置。
  #
  # 这台用的是 Determinate 的 nix,nix-daemon.service 本体是软链到 nix 包里
  # 那份 unit 的。不用自己写 drop-in —— nixpkgs 对这种包提供的 unit 已经
  # 设了 overrideStrategy = "asDropinIfExists",下面这行会自动落到
  # nix-daemon.service.d/overrides.conf 里。
  # (别改成 systemd.units + asDropin,那会和 nixpkgs 的 asDropinIfExists 打架。)
  systemd.services.nix-daemon.serviceConfig.MemoryHigh = "10G";

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

    # **dae 开着的时候 lego 的 DNS-01 一定失败**,所以不做探测,改成定时等待。
    #
    # 根因不在 acme 也不在 Cloudflare,在 dae 劫持 DNS:它把所有 53 端口流量
    # 按自己的 `dns.routing.request` 改道(这里 `fallback: alidns`),**目的
    # 地址被丢弃** —— 除非规则显式写 `-> asis`。而 lego 的传播检查恰恰是
    # "绕开递归缓存、直连权威 NS 问一遍",这个前提被 dae 拆掉了。
    #
    # 实测同一条 dig,应答标志一眼看出:
    #   h610 / shanghai (dae 开) : flags: qr rd ra      ← 递归解析器答的
    #   r5sjp           (dae 关) : flags: qr aa rd      ← 真·Cloudflare 权威
    #
    # 于是 lego 的"问权威 NS"实际问到了 alidns,而 alidns 去查一条刚建几秒、
    # Cloudflare 托管、带 DNSSEC 的记录会返回 SERVFAIL,重试满 2 分钟后放弃
    # —— 从没让 LE 去验证过。手动"停 dae → 跑 order → 开 dae"能成,就是因为
    # 停掉之后劫持消失。
    #
    # --dns.propagation-wait 让 lego 完全不探测,固定等 120s 再让 LE 去验。
    # LE 在境外,那里没有 dae。这样就不用再做那套手动操作了。
    # 120s 是在 shanghai 上拿 LE staging 实测过的。
    #
    # 注意别用 `dnsPropagationCheck = false`:它展开成
    # --dns.propagation-disable-ans,是把检查整个取消而不是换一种做法,lego
    # 建完记录 2 秒就让 LE 去验,记录还没生效 → NXDOMAIN。而且这两个标志互斥。
    defaults.extraLegoFlags = ["--dns.propagation-wait" "120s"];
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
      enable = true;
      adminKey = "hbhbhb";
      webBindAddress = "100.64.0.3";
    };
  };
  # headscale owns 127.0.0.1:8080, so bind the OneBot WS on the docker
  # bridge only; napcat reaches it via host.docker.internal (host-gateway).
  systemd.services.max.environment = {
    MAX_WS_HOST = "172.17.0.1";
    MAX_LOG_COLOR = "always";
    # max 的 GET /api/quota 拿这个问 cliproxy:池子里哪把凭据还在服务、烧完的
    # 什么时候回来。地址不是秘密,写这里;口令在下面的 sops 模板里。
    #
    # 注意 cliproxy 只监听 tailscale 地址(见 modules/cliproxy 里 bindAddress
    # 的说明),所以本机也得走 100.64.0.3,不能写 127.0.0.1。
    MAX_CLIPROXY_BASE_URL = "http://100.64.0.3:8317";
  };

  # 管理口令:和 cliproxy 服务用同一把 sops 密钥,各自渲染一份 env 文件 ——
  # 两边都不进 world-readable 的 nix store,也都不用手改 /var/lib/max-bot。
  sops.templates."max-cliproxy.env" = {
    owner = "max-bot";
    restartUnits = ["max.service"];
    content = ''
      MAX_CLIPROXY_MANAGEMENT_KEY=${config.sops.placeholder."cliproxy/management_key"}
    '';
  };
  # 追加,不是替换:max 模块自己已经设了一个 EnvironmentFile
  # (services.max.environmentFile → /var/lib/max-bot/max-bot.env),而 systemd
  # 的 unitOption 在两边都是列表时按拼接合并。
  systemd.services.max.serviceConfig.EnvironmentFile = [
    config.sops.templates."max-cliproxy.env".path
  ];

  services.qq-deepseek-bot = {
    enable = true;
    environmentFile = "/home/kenneth/services/chat-bot/.env";
    user = "kenneth";
    group = "users";
    host = "172.17.0.1";
    port = 18080;
    sandbox.enable = true;
    browser.enable = true;
    napcat = {
      enable = true;
      account = "3580515978";
      webuiPort = 6100;
    };
  };

  # The monitor and fallback data node live on h610. Tank joins the same
  # formation with a higher candidate priority when it is online. Keep the
  # h610 footprint bounded: its root filesystem has far less room than Tank.
  services.qq-bot-postgres-ha = {
    enable = true;
    passwordFile = config.sops.secrets."qq_bot/postgres_password".path;
    haPasswordFile = config.sops.secrets."qq_bot/ha_password".path;
    monitor.enable = true;
    node = {
      enable = true;
      name = "h610";
      hostname = "100.64.0.3";
      stateDir = "/var/lib/qq-bot-postgres-node";
      dataDir = "/var/lib/qq-bot-postgres-node/data";
      candidatePriority = 50;
      walKeepSize = "1GB";
      maxSlotWalKeepSize = "16GB";
      maxWalSize = "4GB";
      minWalSize = "1GB";
    };
    backup = {
      directory = "/var/lib/qq-bot-postgres-backups";
      retentionDays = 3;
      retentionCount = 1;
      minimumFreeBytes = 30 * 1024 * 1024 * 1024;
    };
  };

  sops.templates."qq-deepseek-bot-postgres.env" = {
    owner = "kenneth";
    group = "users";
    mode = "0400";
    restartUnits = lib.optionals config.systemd.services.qq-deepseek-bot.enable [
      "qq-deepseek-bot.service"
    ];
    content = ''
      AI_POSTGRES_DSN=postgresql://qq_bot:${config.sops.placeholder."qq_bot/postgres_password"}@100.64.0.4:55432,100.64.0.3:55432/qq_bot?target_session_attrs=read-write&connect_timeout=3&sslmode=require
      AI_POSTGRES_SCHEMA=qq_bot
      AI_POSTGRES_POOL_MIN_SIZE=1
      AI_POSTGRES_POOL_MAX_SIZE=10
      AI_POSTGRES_POOL_TIMEOUT_SECONDS=10
      AI_ALLOW_LEGACY_SQLITE=false
      AI_DISABLED_GROUPS=201644592
      AI_ADMIN_ENABLED=true
      AI_SANDBOX_ENABLED=true
      AI_SANDBOX_ALLOWED_USERS=
      AI_SANDBOX_MAX_PER_USER=2
      AI_SANDBOX_MAX_TOTAL=2
      AI_SANDBOX_TIMEOUT_SECONDS=120
      AI_SANDBOX_MAX_FILE_MB=0
      CLIPROXY_API_KEY=${config.sops.placeholder."cliproxy/api_key"}
      AI_MODEL_DEFAULT_PROFILE=deepseek
      AI_MODEL_PROFILES_JSON='${qqBotModelProfiles}'
    '';
  };
  systemd.services.qq-deepseek-bot.serviceConfig.EnvironmentFile = lib.mkAfter [
    config.sops.templates."qq-deepseek-bot-postgres.env".path
  ];
  systemd.services.qq-deepseek-bot.after = lib.mkAfter [
    "tailscaled.service"
    "qq-bot-postgres-bootstrap.service"
  ];
  systemd.services.qq-deepseek-bot.wants = lib.mkAfter [
    "tailscaled.service"
    "qq-bot-postgres-node.service"
  ];

  environment = {
    variables = {
      EDITOR = "nvim";
    };
  };

  environment.systemPackages = with pkgs; [
    gcc
    neovim
    # nginx 删了:services.nginx.enable 已经把它装进 system path 了,再声明一遍
    # 只会让人以为这台上有两个来源。
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

          # 放行经 exit node 的出网流量。shanghai 广播 --advertise-exit-node
          # (见 hosts/shanghai/system.nix),没有这条的话策略层面就把出网挡掉,
          # 广播了也用不了。
          #
          # autogroup:internet **只能出现在 ACL 的 dst**,headscale 源码里有
          # 专门的 ErrAutogroupInternetSrc 拦着放到 src 的写法。
          {
            action = "accept";
            src = ["group:imdomestic"];
            dst = ["autogroup:internet:*"];
          }

          # (可选) 允许所有人访问你广播的特定子网（比如你家的 R6S 局域网）
          # {
          #   action = "accept";
          #   src = [ "group:friends" ];
          #   dst = [ "192.168.1.0/24:*" ];
          # }
        ];

        # Tailscale SSH。**这一段在任何节点开启 `tailscale set --ssh` 之前
        # 完全不生效** —— SSH 规则只对启用了 tailscale SSH 的节点有意义,所以
        # 先落地规则、后开节点,中间没有"开了但没规则"的空窗。
        #
        # 目标是机器之间互相 ssh 不用管密钥:认证走 tailnet 身份,客户端零配置、
        # 零密钥,新机器接进 tailnet 就能用。这也顺带解决 tank 当远程构建机的
        # 认证问题(nix-daemon 以 root 发起 ssh,原本需要一把 root 能读的私钥)。
        #
        # ---------------------------------------------------------------
        # 写法上有三个坑,都是 headscale 特有的,照抄 tailscale 官方示例会踩:
        #
        # 1. **dst 不能用 group。** headscale 的校验里 Group 不是合法的 SSH
        #    destination(实测报 `alias *v2.Group is not supported for SSH
        #    destination`)。允许的是 tag、autogroup:self/member/tagged,
        #    以及"同一个人自己的用户名"。
        #
        #    这里用 `autogroup:member` —— 它是"所有用户拥有的非 tag 节点",
        #    正好覆盖全部机器,**不需要给节点打 tag**。打 tag 反而会出事:
        #    tag 化的节点不再属于 group:imdomestic,上面那条 acl 的 dst 就
        #    匹配不到它们了。
        #
        # 2. **action 必须是 accept,不能是 check。** check 要求发起方每隔
        #    一段时间(默认 12 小时)在浏览器里重新认证一次,会直接打断
        #    deploy-rs 和远程构建这类非交互场景。
        #
        # 3. **`headscale policy check` 是必要条件不是充分条件。** 实测它能
        #    抓住第 1 条(类型错误),但 `action: "check"` 和**漏写 users**
        #    这两种它都照样报 "Policy is valid" —— 尽管源码里就有
        #    ErrSSHUsersMustBeSpecified。所以校验过了不等于行为符合预期。
        # ---------------------------------------------------------------
        #
        # 改这一段要 rebuild + switch h610(策略是 nix store 里的文件)。
        # 需要频繁调试时可以临时切 policy.mode = "database" 用
        # `headscale policy set` 热更新,定稿再切回来。
        ssh = [
          {
            action = "accept";
            src = ["group:imdomestic"];
            dst = ["autogroup:member"];
            # root 要显式列出 —— autogroup:nonroot 的语义是"除 root 外的任何
            # 用户"。deploy-rs 和 nix 远程构建都是以 root 连过去的。
            users = ["root" "autogroup:nonroot"];
          }
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
      derp.paths = [headscaleDerpMap];
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
