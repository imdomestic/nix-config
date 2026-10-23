# What every evaluation (NixOS, nix-darwin, home-manager, system-manager) knows
# about its own host (`config.my.host`) and about the rest of the fleet
# (`config.my.fleet`). The values come from the top-level registry
# (flake/schema/hosts.nix) and are assigned by flake/_lib/host-modules.nix, so
# keep this file free of OS-specific options.
{
  lib,
  config,
  ...
}: {
  options.my.host =
    import ./host-facts.nix {inherit lib;}
    // {
      useChinaMirror = lib.mkOption {
        type = lib.types.bool;
        default = config.my.host.usernames != ["linwhite"];
        defaultText = lib.literalExpression ''config.my.host.usernames != ["linwhite"]'';
        description = "Whether to use the China (SJTU) substituter mirror.";
      };

      users = lib.mkOption {
        type = lib.types.attrsOf lib.types.raw;
        default = {};
        description = "This host's accounts as the registry types them (`hosts.<name>.users`).";
      };

      usernames = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        description = "Accounts to create on this host: the attribute names of `users`.";
      };
    };

  options.my.fleet = {
    hosts = lib.mkOption {
      type = lib.types.attrsOf lib.types.raw;
      default = {};
      description = ''
        Every registry entry's facts (name, system, kind, roles, tsName, ip,
        sshUser, lanRoutes, gpuMonitoring, clusterControl, usernames), for
        modules that need to see past their own host.
      '';
    };

    inventory = lib.mkOption {
      type = lib.types.listOf lib.types.raw;
      default = [];
      description = "The managed hosts (those with a tsName), as built by flake/schema/inventory.nix.";
    };

    placements = lib.mkOption {
      type = lib.types.attrsOf lib.types.raw;
      default = {};
      description = "Where each placed service runs, as built by flake/schema/placements.nix.";
    };
  };
}
