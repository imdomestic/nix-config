# The host registry: one `hosts.<name>` entry per machine, contributed by
# nixos/hosts/<name>/host.nix. The builders in flake/builders turn each entry
# into whichever configurations its `kind` asks for, and flake/_lib/host-modules.nix
# hands the facts to every evaluation as `config.my.host`.
{lib, ...}: let
  inherit (lib) mkOption types;
  tiers = import ../_lib/tiers.nix {inherit lib;};
  guiType = import ../_lib/gui-type.nix {inherit lib;};
  modulesOption = description:
    mkOption {
      type = types.listOf types.raw;
      default = [];
      inherit description;
    };

  accountType = types.submodule {
    options = {
      tier = mkOption {
        type = types.nullOr tiers.type;
        default = null;
        description = "Overrides the account's default tier (`users.<name>.tier`) on this host; `maxTier` still caps it.";
      };
      gui = mkOption {
        type = types.nullOr guiType;
        default = null;
        description = "Replaces the account's GUI layers (`users.<name>.gui.<platform>`) on this host.";
      };
      modules = modulesOption "Home modules only this account on this host gets. They load last.";
      extraGroups = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        description = "Replaces the default groups nixos/modules/users.nix gives the account.";
      };
      nixos = mkOption {
        type = types.attrsOf types.raw;
        default = {};
        description = "Merged into `users.users.<name>` by nixos/modules/users.nix (NixOS and nix-darwin).";
      };
    };
  };

  hostType = types.submodule ({
    name,
    config,
    ...
  }: {
    options =
      import ../../modules/shared/host-facts.nix {inherit lib;}
      // {
        kind = mkOption {
          type = types.enum ["nixos" "darwin" "home"];
          description = "Which system configuration this host gets; `home` means none, only homes.";
        };
        ip = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Address on the WireGuard network, where the host has one.";
        };
        sshUser = mkOption {
          type = types.str;
          default = "root";
          description = "Account deploy-rs connects as.";
        };
        maxTier = mkOption {
          type = tiers.type;
          default = "dev";
          description = "Highest home tier any account gets on this host, for machines too small for the dev toolchain.";
        };

        profiles = modulesOption "System profiles, from `config.flake.modules.<class>`.";
        modules = modulesOption "This host's own system modules.";
        hardwareModules = modulesOption "nixos-hardware modules.";
        externalModules = modulesOption "Third-party modules out of flake inputs.";

        systemManager = {
          enable = lib.mkEnableOption "a system-manager configuration (Linux only)";
          modules = modulesOption "system-manager modules.";
          overlays = mkOption {
            type = types.listOf types.raw;
            default = [];
            description = ''
              nixpkgs overlays for system-manager. They go here and not in
              `nixpkgs.overlays`: system-manager builds pkgs itself, and defining
              overlays on top recurses through users-groups.nix's `pkgs.shadow`.
            '';
          };
        };

        users = mkOption {
          type = types.attrsOf accountType;
          default = {};
          description = "Accounts on this host; each must also have an entry in the top-level `users` table.";
        };
        usernames = mkOption {
          type = types.listOf types.str;
          readOnly = true;
          default = builtins.attrNames config.users;
          description = "The attribute names of `users`.";
        };
      };

    config.name = lib.mkDefault name;
  });

  # Invariants nothing else would catch: each fails silently at runtime.
  check = hosts: let
    routes = lib.concatMap (h: h.lanRoutes) (lib.attrValues hosts);
    dupRoutes = lib.unique (lib.filter (r: lib.count (x: x == r) routes > 1) routes);
    kindMismatch = lib.attrNames (lib.filterAttrs (_: h:
      h.kind != "home" && (h.kind == "darwin") != lib.hasSuffix "darwin" h.system)
    hosts);
  in
    lib.throwIf (dupRoutes != []) "hosts: lanRoutes advertised by more than one host: ${toString dupRoutes}"
    (lib.throwIf (kindMismatch != []) "hosts: kind does not match system for ${toString kindMismatch}"
      hosts);
in {
  options.hosts = mkOption {
    type = types.attrsOf hostType;
    default = {};
    apply = check;
    description = "The host registry.";
  };
}
