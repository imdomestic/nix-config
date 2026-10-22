{
  config,
  lib,
  pkgs,
  ...
}: {
  imports = [./flat-white.nix];
  config = lib.mkIf config.programs.claude-code.enable {
    # 使用原生 settings 描述配置，只合并声明字段，保留运行时写回内容。
    home.file."${config.programs.claude-code.configDir}/settings.json".enable = false;
    home.activation.claudeCodeSettings = lib.hm.dag.entryAfter ["writeBoundary"] ''
      run ${pkgs.python3}/bin/python ${../../../scripts/merge-json-settings.py} \
        ${lib.escapeShellArg "${config.programs.claude-code.configDir}/settings.json"} \
        ${lib.escapeShellArg (builtins.toJSON config.programs.claude-code.settings)}
    '';
  };
}
