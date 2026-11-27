# Key sequences on top of the official programs.rex module, which writes init.lua.
{
  config,
  inputs,
  lib,
  ...
}: let
  cfg = config.programs.rex;
  toLua = lib.generators.toLua {};
in {
  imports = [inputs.rex.homeManagerModules.default];

  options.programs.rex = {
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

  config.programs.rex = {
    # The Rex app ships the CLI and server; terminfo and the ssh guard stay with `rex terminfo setup`.
    package = null;
    config =
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
