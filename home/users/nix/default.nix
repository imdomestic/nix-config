{
  lib,
  inputs,
  system,
  pkgs,
  username,
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
    userName = "Hank Hogan";
    userEmail = "ysh2291939848@outlook.com";
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
    nvim.source = inputs.kvim.outPath;
    hvim.source = inputs.hvim.outPath;
    zsh.source = inputs.zsh-config.outPath;
    neofetch = {
      source = ../../modules/neofetch;
      recursive = true;
    };
    "starship.toml" = {
      source = ../../modules/starship/starship.toml;
    };
  };

  home.sessionVariables = {
    ZDOTDIR =
      if lib.hasInfix "darwin" system
      then "/Users/nix/.config/zsh"
      else "/home/nix/.config/zsh";
  };

  home.file.".local/share/fonts/Recursive-Bold.ttf".source = ../../../fonts/Recursive-Bold.ttf;
  home.file.".local/share/fonts/Recursive-Italic.ttf".source = ../../../fonts/Recursive-Italic.ttf;
  home.file.".local/share/fonts/Recursive-Regular.ttf".source = ../../../fonts/Recursive-Regular.ttf;
  # home.file.wallpapers.source = ../../../wallpapers;
}
