{
  lib,
  inputs,
  system,
  pkgs,
  ...
}: {
  imports = [
    ../../modules/tmux
    # 精简版 nixvim(nix 支持常开);dev.nix 会把 my.nixvim.dev.enable 打开
    ../../modules/nixvim/linwhite.nix
  ];

  home.sessionVariables = {
    ZDOTDIR =
      if lib.hasInfix "darwin" system
      then "/Users/linwhite/.config/zsh"
      else "/home/linwhite/.config/zsh";
  };

  xdg.configFile = {
    zsh.source = inputs.zsh-linwhite.outPath;
    # nvim.source = inputs.nixvim.outPath;
  };

  programs.git = {
    enable = true;
    settings = {
      user.name = "linwhite";
      user.email = "linwhite@linwhite.top";
    };
  };

  programs.zsh.enable = true;

  programs.neovim = {
    enable = true;
    defaultEditor = true;
  };

  programs.starship = {
    enable = true;
    enableTransience = true;
    enableZshIntegration = true;
  };
}
