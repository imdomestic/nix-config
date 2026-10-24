# What an account loads on a GUI host of one platform. Both are the account's
# own modules; they load at different points: `profile` (its GUI layer: apps,
# terminal) before the account's main module, `modules` (desktop tweaks) after
# it (see flake/builders/homes.nix).
{lib}:
lib.types.submodule {
  options = {
    profile = lib.mkOption {
      type = lib.types.nullOr lib.types.raw;
      default = null;
      description = "The account's GUI layer, e.g. `flake.modules.homeManager.hank-gui-darwin`.";
    };
    modules = lib.mkOption {
      type = lib.types.listOf lib.types.raw;
      default = [];
      description = "The account's own desktop modules.";
    };
  };
}
