# Single source of truth for host metadata (`config.my.host`).
# Imported by NixOS, nix-darwin, home-manager and system-manager evals alike,
# so keep it free of OS-specific options.
{
  lib,
  config,
  ...
}: {
  options.my.host = {
    name = lib.mkOption {
      type = lib.types.str;
      description = "Host name (attribute name in the host registry).";
    };

    system = lib.mkOption {
      type = lib.types.str;
      example = "x86_64-linux";
      description = "Platform double of the host.";
    };

    roles = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "Roles this host fulfils, e.g. [\"desktop\" \"gui\"].";
    };

    tsIp = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "100.64.0.3";
      description = ''
        这台机器在 tailnet 里的地址,没有就是 null。

        **设了它就等于纳入监控** —— `nixos/modules/telemetry` 用它当
        node_exporter 的 bind 地址,tank 上的 Prometheus 用它拼抓取目标。
        两边同源,所以不存在"开了 exporter 但没人抓"或者反过来的情况。

        为什么监控走 tailscale 而不是 `ip` 那个 wireguard 地址(10.0.0.0/24):

        - r5sjp 只在 tailnet 上,它是唯一出口,恰恰最该被监控。
        - wg 那张网是经 shanghai 的星型,拿它抓监控等于把这些流量压到
          代理链路上,而代理链路本身正是要被监控的东西。
        - headscale 的 ACL 已经把这四个人圈成 `group:imdomestic`,授权
          模型现成的。

        **必须是 tailscale 地址,不要填 0.0.0.0 或 wg 地址。** r2s/r5s/
        r5sjp/shanghai/r6s/rpi4 这几台是 `firewall.enable = false`,
        `openFirewall` 在它们身上是空操作 —— 绑地址是那里唯一真正起
        作用的边界。参见 modules/cliproxy 里 bindAddress 的同款说明。
      '';
    };

    users = lib.mkOption {
      type = lib.types.attrsOf lib.types.raw;
      default = {};
      description = "Per-user host spec (home profiles/modules, account overrides).";
    };

    usernames = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      description = "Accounts to create on this host; defaults to the attribute names of `users`.";
    };

    homeOverlays = lib.mkOption {
      type = lib.types.listOf lib.types.raw;
      default = [];
      description = "Extra nixpkgs overlays for the home-manager package sets.";
    };
  };

  config.my.host.usernames = lib.mkDefault (builtins.attrNames config.my.host.users);
}
