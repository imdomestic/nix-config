# tailscale + Tailscale SSH。
#
# 原来 `services.tailscale.enable = true` 散在十三台机器的 system.nix 里,
# 抽出来是为了 SSH 这件事能一处开关 —— 它不是"每台随便设一下"的东西:
# 一旦某台开了 `--ssh`,**从 tailnet 地址过去的 22 端口就由 tailscaled 接管**,
# 成败改由 headscale 的策略决定,带密钥也救不回来。这种全局语义必须集中。
#
# 策略在 hosts/h610/system.nix 的 headscale policy 里(`ssh` 段),规则是
# `group:imdomestic → autogroup:member`,users 含 root。
#
# **退路是 wireguard:** 来自 10.0.0.x 的连接仍然走 sshd + publickey,不受
# tailscale SSH 影响。2026-08-08 在 r6s 上的完整实测(零密钥能登、带密钥其实
# 没被用到、审计日志长什么样)见 docs/incidents.md#tailscale-ssh-r6s-probe。
{
  config,
  lib,
  ...
}: let
  cfg = config.my.tailscale;
in {
  imports = [./bind.nix ./guards.nix];

  options.my.tailscale = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = config.my.host.tsName != null;
      defaultText = lib.literalExpression "config.my.host.tsName != null";
      description = ''
        默认跟着 `my.host.tsName` 走 —— 和监控(modules/telemetry)、部署
        (lib/mkDeployNodes.nix)同一个判据,registry 里填一行 tsName,三样一起生效。

        桌面机和 WSL 那几台在 tailnet 里但没有 tsName(它们的 tailnet 节点往往
        是 Windows 那一份,或者压根不是部署目标),需要显式设 true。
      '';
    };

    advertiseRoutes = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = config.my.host.lanRoutes;
      defaultText = lib.literalExpression "config.my.host.lanRoutes";
      example = ["192.168.22.0/24"];
      description = ''
        这台机器要向 tailnet 广播的局域网网段,让 tailnet 里的设备能直接用
        局域网 IP 访问那边**没装 tailscale**的主机。

        默认跟着 registry 里的 `lanRoutes` 走 —— 和 h610 的 headscale policy
        同源,那边遍历同一份 registry 生成 ACL 和 autoApprovers。加一台路由
        只要在 `nixos/hosts/<name>/default.nix` 写一行 `lanRoutes`,广播、
        批准、放行三样一起生效,不会出现"广播了但策略没放行"的半吊子状态。

        **网段在整个 tailnet 里必须唯一。** tailscale 按目的地前缀路由,两台
        广播同一个网段时它只会命中其中一台,而且是静默的,不报错也不告警。
        rpi4(悉尼)和 r5s(国内)原来都是 192.168.20.0/24,这个撞车一度让人
        把"tank 的网关是谁"整个判断错 —— 经过见
        docs/incidents.md#r5s-dae-vless-panic。rpi4 因此改到 192.168.2.0/24。

        **不必是那个网段的网关。** 只要人在网段里就行:tailscale 默认开
        `--snat-subnet-routes`,会把进来的流量伪装成自己的局域网地址,对端
        因此不需要知道 100.64.0.0/10 怎么走。r5sjp 走的正是这条路 —— 它在
        日本只是 10.1.2.0/24 上的一个 DHCP 客户端,网关是别人的设备。

        **广播 ≠ 可用**,还有两步在机器之外:headscale 要批准这条路由
        (h610 的 policy 里有 autoApprovers,新机器自动过),ACL 的 dst 要
        包含这个网段。客户端那边 macOS / iOS 默认接受子网路由,Linux 要
        `tailscale set --accept-routes`。
      '';
    };

    ssh = lib.mkOption {
      type = lib.types.bool;
      default = cfg.enable;
      defaultText = lib.literalExpression "my.tailscale.enable";
      description = ''
        启用 Tailscale SSH,让机器之间互相 ssh 不需要任何密钥。

        **这不是单纯的"多一种登录方式"** —— 开启后 tailnet 来源的 22 端口由
        tailscaled 接管,能不能连完全由 headscale 的 SSH 策略决定。策略写错
        或者被删,所有经 tailnet 地址的 ssh 一起断,包括 deploy-rs
        (它现在正是连 100.64.0.x)。

        不会扩大权限:master authorized_keys 本来就下发到全 fleet 且
        PermitRootLogin = yes,这四个人早就能 root 登任何一台。变的是机制
        (免密钥)和可审计性(记得下是谁),不是谁能进。

        退路:wireguard 的 10.0.0.x 走的是 sshd,不受这个开关影响。
        应急关掉不用 rebuild —— `tailscale set --ssh=false`。
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # 广播子网就得让内核转发起来;不设的话 ip_forward 之类不会被打开,
    # 广播了也转不动。和 shanghai 的 exit node 是同一个开关。
    services.tailscale.useRoutingFeatures = lib.mkIf (cfg.advertiseRoutes != []) "server";

    services.tailscale = {
      enable = true;

      # 用 extraSetFlags 不用 extraUpFlags:后者在 nixpkgs 的模块里**只有设了
      # authKeyFile 才会被应用**,这些机器都没设,写 extraUpFlags 会被静默忽略。
      # extraSetFlags 走的是独立的 tailscaled-set.service,跑 `tailscale set`。
      extraSetFlags =
        ["--accept-dns=true"]
        ++ lib.optionals cfg.ssh ["--ssh"]
        ++ lib.optional (cfg.advertiseRoutes != []) "--advertise-routes=${lib.concatStringsSep "," cfg.advertiseRoutes}";
    };
  };
}
