{
  lib,
  inputs,
  pkgs,
  ...
}: {
  home.packages = with pkgs; [
    lua-language-server
    nil
    alejandra
    duf
    just
    starship
  ];

  programs.git = {
    enable = true;
    settings = {
      user.name = "Hank Hogan";
      user.email = "ysh2291939848@outlook.com";
    };
  };

  programs.neovim = {
    enable = true;
    defaultEditor = true;
  };

  programs.starship = {
    enable = true;
    enableTransience = true;
    enableZshIntegration = true;
  };

  programs.kitty.enable = true;

  xdg.configFile = {
    zsh.source = inputs.zsh-hank.outPath;
    fastfetch = {
      source = ./modules/fastfetch;
      recursive = true;
    };
  };

  home.sessionVariables = {
    ZDOTDIR =
      if pkgs.stdenv.isDarwin
      then "/Users/nix/.config/zsh"
      else "/home/nix/.config/zsh";
  };
}
