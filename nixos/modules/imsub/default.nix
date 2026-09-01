# 自用订阅。和 modules/airport 是两回事:那个发给朋友,一个节点、有配额、有
# 到期;这个发给我自己,节点全给、永久有效、带完整分流规则。
#
# 存在的理由是「改一处、所有客户端跟着变」。以前 Mac 上的 clash 和手机上的
# Egern 各存一份手抄配置,加一台机器就要手动补两处 —— r2s 上线之后两边都漏了,
# 这个模块就是把那两份配置收编成仓库里的唯一真相。
#
# 凭据一律不进 nix store:配置整体由 sops.templates 渲染,占位符在激活时才被
# 替换成真值。订阅服务只负责核 token、发文件,见 ./server.py。
{
  config,
  lib,
  pkgs,
  ...
}:
with lib; let
  cfg = config.services.imsub;

  # 节点凭据,和 modules/mihomo、modules/singbox 共用同一个 sops 文件
  # (按 .sops.yaml 的兜底规则加密给全部 admin + 全部 host)。名单本身在
  # ../im-nodes.nix,三个模块共用一份;列表顺序就是客户端里的显示顺序。
  nodes = import ../im-nodes.nix;
  nodeFields = ["uuid" "public_key" "short_id"];

  s = config.sops.placeholder;
  sec = node: field: s."imdomestic/${node.secret}/${field}";

  tags = map (n: "imdomestic-${n.name}") nodes;

  # **每个出口一个自动测速组,两个出口之间只手动切。** 自动组只比延迟,而这
  # 两条线延迟和吞吐是反的:悉尼延迟更低,吞吐却只有日本的 1/3 到 1/7(同一台
  # h610 实测,见 docs/decisions.md#au-exit-separate-auto-group)。所以组内择优
  # 交给客户端,跨出口的取舍留给人。
  tagsOf = exit: map (n: "imdomestic-${n.name}") (filter (n: n.exit == exit) nodes);
  jpTags = tagsOf "jp";
  auTags = tagsOf "au";

  # 缩进一整块文本。空行保持空,免得留下一串只有空格的行。
  indent = pad: text:
    concatStringsSep "\n"
    (map (l:
      if l == ""
      then ""
      else pad + l)
    (splitString "\n" (removeSuffix "\n" text)));

  # 占位符**必须**放在双引号里。sops 做的是纯文本替换,不加引号的话,一个碰巧
  # 全是数字的 short_id 会被 YAML 解析成整数,客户端那边就报类型错误。
  clashProxy = node: ''
    - name: "imdomestic-${node.name}"
      type: vless
      server: ${node.host}
      port: ${toString node.port}
      uuid: "${sec node "uuid"}"
      network: tcp
      tls: true
      udp: true
      xudp: true
      flow: xtls-rprx-vision
      servername: www.aliyun.com
      client-fingerprint: chrome
      reality-opts:
        public-key: "${sec node "public_key"}"
        short-id: "${sec node "short_id"}"
  '';

  egernProxy = node: ''
    - vless:
        name: imdomestic-${node.name}
        server: ${node.host}
        port: ${toString node.port}
        user_id: "${sec node "uuid"}"
        tfo: false
        udp_relay: true
        flow: xtls-rprx-vision
        transport:
          tls:
            sni: www.aliyun.com
            reality:
              public_key: "${sec node "public_key"}"
              short_id: "${sec node "short_id"}"
            skip_tls_verify: false
  '';

  # clash 的 proxies 是 2 空格缩进的列表,egern 的顶格。
  clashProxies = concatMapStringsSep "\n" (n: indent "  " (clashProxy n)) nodes;
  egernProxies = concatMapStringsSep "\n" (n: indent "" (egernProxy n)) nodes;

  clashTags = concatMapStringsSep "\n" (t: "      - ${t}") tags;
  egernTags = concatMapStringsSep "\n" (t: "    - ${t}") tags;

  clashJpTags = concatMapStringsSep "\n" (t: "      - ${t}") jpTags;
  clashAuTags = concatMapStringsSep "\n" (t: "      - ${t}") auTags;
  egernJpTags = concatMapStringsSep "\n" (t: "    - ${t}") jpTags;
  egernAuTags = concatMapStringsSep "\n" (t: "    - ${t}") auTags;

  # 拦 QUIC(UDP/443)。`sub` 为 null 时无条件拦,否则再 AND 上一条子规则。
  #
  # **只在「这条流量最终要出国」时才拦。** 拦它的唯一理由是逼客户端回退到 TCP
  # —— 反向隧道对 UDP 支持差。对直连目标拦它是纯亏,而且 REJECT 对 UDP 是静默
  # 丢包,客户端只能干等 QUIC 超时,见 docs/incidents.md#quic-blackhole。
  #
  # 拆成多处而不是开头一条,是因为下面 DIRECT / im 的规则是交错的,没有单一
  # 插入点能把两者分开。形状和 modules/mihomo 里那份一致,改一边记得看另一边。
  quicReject = sub: let
    parts = ["(NETWORK,UDP)" "(DST-PORT,443)"] ++ optional (sub != null) sub;
  in "AND,(${concatStringsSep "," parts}),REJECT";

  # 走 im 组的 geosite。每个生成两条:先拦掉它的 QUIC,再把它的 TCP 送进代理。
  # 两条写在一起是为了改不漏 —— 新增一条 `,im` 规则时照抄这个形状即可。
  proxiedSites = ["github" "google-gemini" "google" "telegram"];
  proxiedRules = concatMapStringsSep "\n" (tag:
    concatStringsSep "\n" [
      "  - ${quicReject "(GEOSITE,${tag})"}"
      "  - GEOSITE,${tag},im"
    ])
  proxiedSites;

  clashConfig = ''
    # 由 nix-config 的 nixos/modules/imsub 生成,别手改 —— 下次拉订阅就没了。
    port: 7890
    socks-port: 7891
    mixed-port: 7893
    allow-lan: true
    mode: rule
    log-level: info
    ipv6: true

    # 外部控制 (GUI 需要)
    external-controller: 127.0.0.1:9090

    dns:
      enable: true
      ipv6: true
      listen: 0.0.0.0:1053
      enhanced-mode: fake-ip
      fake-ip-range: 198.18.0.1/16
      # 自建域名不能进 fake-ip:下面 imdomestic.com 走 DIRECT,需要真实 IP。
      # 订阅地址本身也在这个域名下,拿到假 IP 就更新不了订阅。
      fake-ip-filter:
        - "*.imdomestic.com"
      nameserver:
        - 223.5.5.5
        - 119.29.29.29
        - 8.8.8.8

    # 端口 54322 = 各 portal 的 client-in2 入口(经隧道从 r5sjp 出);
    # 54324 = client-au(经隧道从 rpi4 出)。每台每口的 uuid / public-key /
    # short-id 都是独立的,不共用。
    proxies:
    ${clashProxies}

    proxy-groups:
      - name: im
        type: select
        proxies:
          - auto-jp
          - auto-au
    ${clashTags}

      # 组内各节点分处不同运营商和线路,延迟差别不小,自动择优比手动切实用。
      # 但两个出口不合并:url-test 只比延迟,而悉尼延迟更低、吞吐只有日本的
      # 1/3 到 1/7。要用澳洲 IP 就手动选 auto-au,平时留在 auto-jp。
      - name: auto-jp
        type: url-test
        url: http://cp.cloudflare.com/generate_204
        interval: 300
        tolerance: 100
        proxies:
    ${clashJpTags}

      - name: auto-au
        type: url-test
        url: http://cp.cloudflare.com/generate_204
        interval: 300
        tolerance: 100
        proxies:
    ${clashAuTags}

    rules:
      # ===== 广告屏蔽 =====
      # QUIC 的拦截不在这里 —— 它按目的地分散在下面,见 quicReject 的说明。
      - GEOSITE,category-ads-all,REJECT

      # ===== 自建基础设施直连 =====
      # 必须排在 MATCH,im 之前。没有这条的话,SSH 到 <host>.imdomestic.com 会被
      # 兜底规则丢进 im 组,而 im 组本身就是经 portal -> 反向隧道 -> r5sjp;于是
      # 隧道一断,用来修隧道的 SSH 也跟着断。dae 那边踩过一次,规则同源。
      - DOMAIN-SUFFIX,imdomestic.com,DIRECT

      # ===== Tailscale 规则 =====
      - IP-CIDR,100.100.100.100/32,DIRECT,no-resolve
      - SRC-PORT,41641,DIRECT
      - DST-PORT,41641,DIRECT
      - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
      - IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve
      - PROCESS-NAME,tailscaled,DIRECT
      - PROCESS-NAME,tailscale,DIRECT

      # ===== 国内 DNS & 本地 IP 直连 =====
      - IP-CIDR,223.5.5.5/32,DIRECT,no-resolve
      - IP-CIDR,223.6.6.6/32,DIRECT,no-resolve
      - IP-CIDR,119.29.29.29/32,DIRECT,no-resolve
      - IP-CIDR,224.0.0.0/4,DIRECT,no-resolve
      - IP-CIDR6,ff00::/8,DIRECT,no-resolve
      - GEOIP,private,DIRECT,no-resolve

      # ===== 特定应用代理 (走 im 策略组) =====
    ${proxiedRules}

      # ===== 国内网站 & 游戏平台直连 =====
      - GEOSITE,cn,DIRECT
      - GEOSITE,bilibili,DIRECT
      - GEOSITE,steam,DIRECT
      - GEOSITE,steam@cn,DIRECT
      - GEOSITE,epicgames,DIRECT
      - GEOSITE,ea,DIRECT
      - GEOSITE,ubisoft,DIRECT
      - GEOSITE,apple,DIRECT
      - GEOSITE,apple@cn,DIRECT
      - GEOSITE,microsoft,DIRECT
      - GEOIP,cn,DIRECT

      # ===== Fallback 兜底规则 =====
      # 到这里还没匹配上的都要走下面的 MATCH,im 出国,所以拦掉它们的 QUIC。
      - ${quicReject null}
      - MATCH,im
  '';

  egernConfig = ''
    # 由 nix-config 的 nixos/modules/imsub 生成,别手改 —— 下次拉订阅就没了。
    ipv6: true
    http_port: 3080
    socks_port: 3090
    allow_external_connections: true

    # fake-ip 在 Egern 里常开且没有开关,排除列表是这个顶层键(不在 dns: 下面)。
    # 下面 imdomestic.com 走 DIRECT,必须拿到真实 IP,否则连的是 fake-ip 假地址。
    real_ip_domains:
      - "*.imdomestic.com"

    dns: {}

    proxies:
    ${egernProxies}

    # Egern 的自动测速组叫 smart,测试地址的键是 latency_test_url —— 不是
    # clash 那边的 url-test / url。
    # 组名沿用这个文件里的大写惯例(PROXY / AUTO-*),和 clash 那边的
    # auto-jp / auto-au 是同一组东西。
    policy_groups:
    - smart:
        name: AUTO-JP
        policies:
    ${egernJpTags}
        latency_test_url: http://cp.cloudflare.com/generate_204
        hidden: true
    - smart:
        name: AUTO-AU
        policies:
    ${egernAuTags}
        latency_test_url: http://cp.cloudflare.com/generate_204
        hidden: true
    - select:
        name: PROXY
        policies:
        - AUTO-JP
        - AUTO-AU
    ${egernTags}
        flatten: false
        hidden: false

    rules:
    # 自建基础设施直连,必须排在 default 之前。手机上大概不 SSH,但订阅
    # (h610:8443) 和 headscale 都在这个域名下,隧道一断就够不着了。
    - domain_suffix:
        match: imdomestic.com
        policy: DIRECT
    - ip_cidr:
        match: 192.168.0.0/16
        policy: DIRECT
    - ip_cidr:
        match: 10.0.0.0/8
        policy: DIRECT
    - ip_cidr:
        match: 127.0.0.0/8
        policy: DIRECT
    - ip_cidr:
        match: 172.16.0.0/12
        policy: DIRECT
    - ip_cidr:
        match: 192.128.0.0/16
        policy: DIRECT
    - ip_cidr:
        match: 224.0.0.0/24
        policy: DIRECT
    - geoip:
        match: CN
        policy: DIRECT
    - default:
        policy: PROXY
    default_proxy_group: PROXY
  '';

  formats = {
    clash = config.sops.templates."imsub-clash.yaml".path;
    egern = config.sops.templates."imsub-egern.yaml".path;
  };

  # 进 store 的只有这些:监听地址、路径前缀、以及去哪儿读 token 和配置。
  # 一个秘密都没有。
  configFile = pkgs.writeText "imsub.json" (builtins.toJSON {
    inherit formats;
    inherit (cfg) listen profileName updateInterval;
    prefix = cfg.pathPrefix;
    tokenFile = toString cfg.tokenFile;
  });

  python = "${pkgs.python3}/bin/python3";

  # token 只在这台机器上,所以链接也只能在这台机器上拼出来。
  # 文件是 imsub 用户 0400,普通用户读不了 —— 要 sudo。
  imsubUrl = pkgs.writeShellScriptBin "imsub-url" ''
    set -eu
    token=$(cat ${toString cfg.tokenFile})
    ${concatMapStrings (f: ''
      printf '%-6s %s\n' ${escapeShellArg f} "${cfg.baseUrl}/${cfg.pathPrefix}/$token/${f}"
    '') (attrNames formats)}
  '';
in {
  options.services.imsub = {
    enable = mkEnableOption "自用订阅服务(clash / egern)";

    listen = mkOption {
      type = types.str;
      default = "127.0.0.1:8082";
      description = "只听回环,TLS 和限速交给前面的 nginx。";
    };

    pathPrefix = mkOption {
      type = types.str;
      default = "imsub";
      description = ''
        URL 的第一段,形如 <baseUrl>/<pathPrefix>/<token>/<format>。
        和 modules/airport 的 /sub/ 错开,好让 nginx 分别限速。
      '';
    };

    baseUrl = mkOption {
      type = types.str;
      example = "https://h610.imdomestic.com:8443";
      description = "对外的订阅前缀,只用来给 `imsub-url` 拼链接。";
    };

    tokenFile = mkOption {
      type = types.path;
      description = ''
        订阅 token 文件,需要 imsub 用户可读。这是唯一的认证,所以它既是
        「密码」也是「订阅地址」的一部分 —— 换掉它等于吊销全部旧链接。
      '';
    };

    profileName = mkOption {
      type = types.str;
      default = "imdomestic";
      description = "客户端新建配置时的默认名字(走 Content-Disposition)。";
    };

    updateInterval = mkOption {
      type = types.ints.positive;
      default = 24;
      description = "建议客户端多久拉一次(小时)。";
    };
  };

  config = mkIf cfg.enable {
    users.users.imsub = {
      isSystemUser = true;
      group = "imsub";
      description = "自用订阅服务";
    };
    users.groups.imsub = {};

    # 各节点的凭据。mihomo / singbox 模块声明的是同名同文件的 secret,
    # 同一台机器上同时开也不冲突(定义相同,模块系统直接合并)。
    #
    # 这里不设 restartUnits:服务读的是下面渲染出来的成品,而且每次请求都重新
    # 打开文件,所以换了凭据只要激活过一次就生效,不用重启。
    sops.secrets = listToAttrs (concatMap (node:
      map (field: {
        name = "imdomestic/${node.secret}/${field}";
        value.sopsFile = ../../../secrets/clients/imdomestic.yaml;
      })
      nodeFields)
    nodes);

    # 渲染成品直接落在 /run,服务只读不拼 —— 所以进程本身不需要任何解密能力。
    sops.templates."imsub-clash.yaml" = {
      owner = "imsub";
      content = clashConfig;
    };
    sops.templates."imsub-egern.yaml" = {
      owner = "imsub";
      content = egernConfig;
    };

    systemd.services.imsub = {
      description = "自用订阅服务";
      after = ["network.target"];
      wantedBy = ["multi-user.target"];
      environment.IMSUB_CONFIG = "${configFile}";
      serviceConfig = {
        Type = "simple";
        User = "imsub";
        Group = "imsub";
        ExecStart = "${python} ${./server.py}";
        Restart = "always";
        RestartSec = "5s";
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        NoNewPrivileges = true;
        RestrictAddressFamilies = ["AF_INET" "AF_INET6"];
      };
    };

    environment.systemPackages = [imsubUrl];
  };
}
