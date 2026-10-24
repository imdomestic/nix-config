# The account table. Each entry lives in home/users/<account>/user.nix and says
# who the person is (tier, keys); what their home is made of is the files in
# that directory, picked by name in flake/builders/homes.nix. A host only says
# which accounts it has (`hosts.<name>.users`).
{lib, ...}: let
  inherit (lib) mkOption types;
  tiers = import ../_lib/tiers.nix {inherit lib;};
in {
  options.users = mkOption {
    type = types.attrsOf (types.submodule ({name, ...}: {
      options = {
        tier = mkOption {
          type = tiers.type;
          default = "interactive";
          description = "Default tier; a host can lower it per account or cap it with `maxTier`.";
        };
        dir = mkOption {
          type = types.path;
          default = ../../home/users + "/${name}";
          defaultText = lib.literalExpression ''../../home/users + "/<account>"'';
          description = ''
            The account's home directory in this repo: default.nix, the tier
            and GUI files, <host>.nix and modules/. Another name for the same
            person on one machine points it at that person's directory.
          '';
        };
        sshKeys = mkOption {
          type = types.listOf types.str;
          default = [];
          description = ''
            Public keys that may log in as this account, on every host it has
            an account on. Keys in system/modules/ssh/keys.nix work for every
            account instead, root included.
          '';
        };
        ageKeys = mkOption {
          type = types.attrsOf (types.strMatching "age1[0-9a-z]{58}");
          default = {};
          description = ''
            sops keys of this person that belong to no registry machine, by label.
            Keys tied to a machine go on that host's account entry instead
            (`hosts.<name>.users.<account>.ageKey`).
          '';
        };
      };
    }));
    default = {};
    description = "Accounts, by account name.";
  };
}
