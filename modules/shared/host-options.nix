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

    lanRoutes = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      example = ["192.168.22.0/24"];
      description = ''
        这台机器背后的局域网网段,会由 `nixos/modules/tailscale` 向 tailnet
        广播,让别处的设备直接用局域网 IP 访问那边**没装 tailscale**的主机。

        放在 registry 而不是各自的 system.nix,是因为它有**两个**消费方:
        广播那一端在 tailscale 模块,批准和放行那一端在 h610 的 headscale
        policy。policy 直接遍历整份 registry 生成 ACL 和 autoApprovers,
        所以加一台路由只要在这里写一行,不用记得再去改 h610。

        **网段在整个 tailnet 里必须唯一。** tailscale 按目的地前缀路由,两台
        广播同一段时只会命中一台,静默,不报错。rpi4 和 r5s 原来都是
        192.168.20.0/24,这个撞车让人把"tank 的网关是谁"整个判断错 ——
        见 docs/incidents.md#r5s-dae-vless-panic。rpi4 因此改到 192.168.2.0/24。
      '';
    };

    tsName = lib.mkOption {
      type = lib.types.nullOr (lib.types.strMatching "[a-z0-9-]+([.][a-z0-9-]+)+");
      default = null;
      example = "h610.inner.imdomestic.com";
      description = ''
        Fully qualified MagicDNS name. A non-null name opts this host into
        Tailscale, deployment and telemetry. Connections use this name; listeners
        resolve it at startup. No allocated Tailscale IP belongs in the registry.
        See docs/tailscale-names.md for DNS readiness and IP-only applications.
      '';
    };

    gpuMonitoring = {
      enable = lib.mkEnableOption "NVIDIA GPU telemetry, dashboards and alerts";
      uuids = lib.mkOption {
        type = lib.types.listOf (lib.types.strMatching "GPU-[0-9a-fA-F-]+");
        default = [];
        example = ["GPU-d8ec4dea-3771-68e6-9f8b-11811e47ac9d"];
        description = "GPU UUID allowlist; empty discovers all GPUs. Explicit UUIDs also detect a missing card.";
      };
    };

    clusterControl = {
      enable = lib.mkEnableOption "Gaoji cluster control inventory for this host";
      manageableUnits = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "Exact services permitted for typed start/stop/restart/reload jobs.";
      };
      readableUnits = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "Additional exact units to observe, including when they are not loaded.";
      };
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
