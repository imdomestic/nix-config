{username}: {
  inputs,
  system,
  pkgs,
  ...
}: let
  lib = inputs.nixpkgs.lib;
in {
  imports =
    [
      ./core.nix
      ./base/home.nix
    ]
    ++ lib.optional (lib.hasInfix "linux" system) ./linux/home.nix
    ++ lib.optional (lib.hasInfix "darwin" system) ./darwin/home.nix;

  _module.args = {
    inherit inputs system username;
  };

  programs.git = {
    enable = true;
    userName = "Hank Hogan";
    userEmail = "ysh2291939848@outlook.com";
  };

  programs.jujutsu = {
    enable = true;
    settings = {
      aliases.tug = ["bookmark" "move" "--from" "heads(::@- & bookmarks())" "--to" "@-"];
      ui = {
        paginate = "never";
        default-command = "log";
      };
      user = {
        email = "hnkhgn@icloud.com";
        name = "Hank Hogan";
      };
    };
  };

  programs.emacs = {
    enable = false;
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

  xdg.configFile = {
    nvim.source = inputs.kvim.outPath;
    hvim.source = inputs.hvim.outPath;
    zsh.source = inputs.zsh-config.outPath;
    wezterm.source = inputs.wezterm-config.outPath;
    neofetch = {
      source = ../modules/neofetch;
      recursive = true;
    };
    "starship.toml" = {
      source = ../modules/starship/starship.toml;
    };
  };

  home.file.".zshenv".text = ''
    ZDOTDIR=$HOME/.config/zsh
  '';

  home.file.".local/share/fonts/Recursive-Bold.ttf".source = ../fonts/Recursive-Bold.ttf;
  home.file.".local/share/fonts/Recursive-Italic.ttf".source = ../fonts/Recursive-Italic.ttf;
  home.file.".local/share/fonts/Recursive-Regular.ttf".source = ../fonts/Recursive-Regular.ttf;
  home.file.wallpapers.source = ../wallpapers;

  home.packages = with pkgs; [
  ];
}
