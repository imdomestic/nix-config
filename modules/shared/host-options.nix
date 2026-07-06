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
