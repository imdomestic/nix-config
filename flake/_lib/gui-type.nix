# What an account loads on a GUI host of one platform. The two fields load at
# different points: `profile` is a shared bundle from home/profiles/gui and
# loads before the account's own module, `modules` are the account's own
# desktop tweaks and load after it (see flake/builders/homes.nix).
{lib}:
lib.types.submodule {
  options = {
    profile = lib.mkOption {
      type = lib.types.nullOr lib.types.raw;
      default = null;
      description = "Shared GUI bundle, e.g. `flake.modules.homeManager.gui-darwin`.";
    };
    modules = lib.mkOption {
      type = lib.types.listOf lib.types.raw;
      default = [];
      description = "The account's own desktop modules.";
    };
  };
}
