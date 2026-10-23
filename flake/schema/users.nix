# The account table: what an account's home is made of wherever it exists.
# Entries live next to the account's modules, in home/users/<dir>/user.nix; a
# host only says which accounts it has (`hosts.<name>.users`) and where they
# differ there. Composition: flake/builders/homes.nix.
{lib, ...}: let
  inherit (lib) mkOption types;
  tiers = import ../_lib/tiers.nix {inherit lib;};
  guiType = import ../_lib/gui-type.nix {inherit lib;};
in {
  options.users = mkOption {
    type = types.attrsOf (types.submodule {
      options = {
        tier = mkOption {
          type = tiers.type;
          default = "interactive";
          description = "Default tier; a host can lower it per account or cap it with `maxTier`.";
        };
        module = mkOption {
          type = types.raw;
          description = "The account's own home module, loaded on every host.";
        };
        dev = mkOption {
          type = types.nullOr types.raw;
          default = null;
          description = "Loaded at the dev tier in place of home/profiles/dev.nix, which it is expected to import.";
        };
        gui = {
          linux = mkOption {
            type = guiType;
            default = {};
            description = "Loaded on Linux hosts with the `gui` role.";
          };
          darwin = mkOption {
            type = guiType;
            default = {};
            description = "Loaded on macOS hosts with the `gui` role.";
          };
        };
      };
    });
    default = {};
    description = "Accounts, by account name.";
  };
}
