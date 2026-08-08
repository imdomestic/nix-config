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
# ---------------------------------------------------------------------------
# 2026-08-08 在 r6s 上实测过的行为,记在这里免得以后重新推一遍:
#
#   - 不带任何密钥(IdentityFile=/nonexistent + IdentityAgent=none)能以 root
#     登进去 —— 认证确实走 tailnet 身份。
#   - **带密钥的 ssh 也照常能连**,但日志显示它同样是 tailscaled 处理的,
#     只是策略放行了 —— 那把密钥根本没被用到。
#   - 来自 wireguard 地址(10.0.0.x)的连接仍然走 sshd,publickey 认证,
#     完全不受影响。这是永远的退路。
#   - 附带好处:tailscaled 会记 `audit: SSH login: user=root ...
#     ts_user=hank@imdomestic.com node=h610...`。以前四个人共用一份 master
#     authorized_keys 登 root,日志里分不出是谁,现在分得出。
# ---------------------------------------------------------------------------
{
  config,
  lib,
  ...
}: let
  cfg = config.my.tailscale;
in {
  options.my.tailscale = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = config.my.host.tsIp != null;
      defaultText = lib.literalExpression "config.my.host.tsIp != null";
      description = ''
        默认跟着 `my.host.tsIp` 走 —— 和监控(modules/telemetry)、部署
        (lib/mkDeployNodes.nix)同一个判据,registry 里填一行 tsIp,三样一起生效。

        桌面机和 WSL 那几台在 tailnet 里但没有 tsIp(它们的 tailnet 节点往往
        是 Windows 那一份,或者压根不是部署目标),需要显式设 true。
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
    services.tailscale = {
      enable = true;

      # 用 extraSetFlags 不用 extraUpFlags:后者在 nixpkgs 的模块里**只有设了
      # authKeyFile 才会被应用**,这些机器都没设,写 extraUpFlags 会被静默忽略。
      # extraSetFlags 走的是独立的 tailscaled-set.service,跑 `tailscale set`。
      extraSetFlags = lib.optionals cfg.ssh ["--ssh"];
    };
  };
}
