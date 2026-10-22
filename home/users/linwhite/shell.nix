{
  config,
  inputs,
  lib,
  ...
}: {
  home.sessionVariables.ZDOTDIR = config.home.homeDirectory;
  # HM 接管入口，保留外部仓库的行为片段；配色与 prompt 由本仓库管理。
  programs.zsh = {
    # 沿用 HM 已管理的 ~/.zshrc，避免在旧 .config/zsh 整目录 store 链接里写文件。
    dotDir = config.home.homeDirectory;
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
      export STARSHIP_CONFIG="${config.xdg.configHome}/starship.toml"
      export starship_config="$STARSHIP_CONFIG"
    '';
  };
}
