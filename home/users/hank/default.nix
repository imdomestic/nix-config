{
  lib,
  inputs,
  username,
  system,
  pkgs,
  ...
}: {
  programs.git = {
    enable = true;
    settings = {
      user.name = "Hank Hogan";
      user.email = "ysh2291939848@outlook.com";
    };
  };

  programs.jujutsu = {
    enable = true;
    settings = {
      aliases = {
        tug = ["bookmark" "move" "--from" "heads(::@- & bookmarks())" "--to" "@-"];
        rebase-all = ["rebase" "-s" "all:roots(trunk()..mutable())" "-d" "trunk()"];
      };
      ui = {
        diff-formatter = "git";
        paginate = "never";
        default-command = "log";
      };
      revset-aliases = {
        at = "@";
        "user(x)" = "author(x) | committer(x)";
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
    zsh.source = inputs.zsh-config.outPath;
    wezterm.source = inputs.wezterm-config.outPath;
    neofetch = {
      source = ../../modules/neofetch;
      recursive = true;
    };
    "starship.toml" = {
      source = ../../modules/starship/starship.toml;
    };
  };

  # home.file.".zshenv".source = ../../modules/zsh/.zshenv;
  home.sessionVariables = {
    ZDOTDIR =
      if lib.hasInfix "darwin" system
      then "/Users/hank/.config/zsh"
      else "/home/hank/.config/zsh";
  };

  home.file.".local/share/fonts/Recursive-Bold.ttf".source = ../../../fonts/Recursive-Bold.ttf;
  home.file.".local/share/fonts/Recursive-Italic.ttf".source = ../../../fonts/Recursive-Italic.ttf;
  home.file.".local/share/fonts/Recursive-Regular.ttf".source = ../../../fonts/Recursive-Regular.ttf;
  home.file.wallpapers.source = ../../../wallpapers;

  home.packages = with pkgs; [
  ];
}
