{
  lib,
  inputs,
  system,
  pkgs,
  ...
}: {
  home.sessionVariables = {
    ZDOTDIR =
      if lib.hasInfix "darwin" system
      then "/Users/linwhite/.config/zsh"
      else "/home/linwhite/.config/zsh";
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
