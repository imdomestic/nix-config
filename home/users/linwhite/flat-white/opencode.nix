{
  config,
  lib,
  ...
}: {
  config = lib.mkIf config.programs.opencode.enable {
    programs.opencode.themes.flat-white = import ./opencode-theme.nix {inherit lib;};
    # HM 尚无 V2 cli 选项；使用官方 inline 配置，并正确引用 JSON。
    home.sessionVariablesExtra = ''
      export OPENCODE_CLI_CONFIG_CONTENT=${lib.escapeShellArg (builtins.toJSON {
        theme = {
          name = "flat-white";
          mode = "dark";
        };
      })}
    '';
  };
}
