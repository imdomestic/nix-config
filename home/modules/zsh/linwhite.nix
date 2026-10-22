{
  config,
  inputs,
  lib,
  ...
}: {
  imports = [./flat-white.nix];
  # HM 接管入口，保留外部仓库的行为片段；配色与 prompt 由本仓库管理。
  programs.zsh = {
    # 由原生模块生成 ZDOTDIR 入口；见 docs/incidents.md#linwhite-tmux-stale-zdotdir。
    enable = true;
    dotDir = "${config.xdg.configHome}/zsh";
    enableCompletion = false;
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
    initContent = lib.mkOrder 500 ''
      for _linwhite_part in env aliases utility options plugins keybinds; do
        source "${inputs.zsh-linwhite}/$_linwhite_part.zsh"
      done
      unset _linwhite_part
      export STARSHIP_CONFIG=${lib.escapeShellArg config.programs.starship.configPath}
      export starship_config="$STARSHIP_CONFIG"
    '';
  };
}
