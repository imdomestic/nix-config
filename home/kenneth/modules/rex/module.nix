{
  config,
  lib,
  ...
}: let
  cfg = config.programs.rex;
  toLua = lib.generators.toLua {};
in {
  options.programs.rex = {
    enable = lib.mkEnableOption "Rex configuration";
    bindings = lib.mkOption {
      default = {};
      description = "Rex key sequences and the actions they perform.";
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          action = lib.mkOption {type = lib.types.str;};
          args = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = {};
            description = "Arguments accepted by the Rex action.";
          };
        };
      });
    };
    extraConfig = lib.mkOption {
      type = lib.types.lines;
      default = "";
      description = "Additional Lua for actions not provided by Rex.";
    };
  };

  config = lib.mkIf cfg.enable {
    xdg.configFile."rex/init.lua".text =
      cfg.extraConfig
      + "\n"
      + lib.concatMapAttrsStringSep "\n" (key: binding:
        "rex.bind(${toLua key}, ${toLua binding.action}"
        + lib.optionalString (binding.args != {}) ", ${toLua binding.args}"
        + ")")
      cfg.bindings
      + "\n";
  };
}
