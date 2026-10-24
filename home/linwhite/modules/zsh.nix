{
  config,
  inputs,
  lib,
  ...
}: {
  programs.zsh = {
    enable = true;
    dotDir = "${config.xdg.configHome}/zsh";
    enableCompletion = false;
    profileExtra = ''
      source "${inputs.zsh-linwhite}/.zprofile"
    '';
    # 行为片段先于 Home Manager 工具集成加载，提示符由 Starship 模块初始化。
    initContent = lib.mkOrder 500 ''
      for _linwhite_part in theme env aliases utility options plugins keybinds highlight; do
        source "${inputs.zsh-linwhite}/$_linwhite_part.zsh" || return
      done
      unset _linwhite_part
      export STARSHIP_CONFIG=${lib.escapeShellArg config.programs.starship.configPath}
      export starship_config="$STARSHIP_CONFIG"
    '';
    history = {
      path = "${config.xdg.cacheHome}/zsh/.zhistory";
      size = 10000;
      save = 10000;
      append = true;
      extended = true;
      ignoreAllDups = true;
      saveNoDups = true;
      expireDuplicatesFirst = true;
    };
  };
}
