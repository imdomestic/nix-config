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
}
