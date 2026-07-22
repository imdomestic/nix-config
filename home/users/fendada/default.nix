{
  lib,
  pkgs,
  ...
}: let
  isDarwin = pkgs.stdenv.isDarwin;
  dotfiles = ./dotfiles;
in
  lib.mkMerge [
    {
      programs.git = {
        enable = true;
        settings = {
          user = {
            name = "fen-dada";
            email = "1823215739@qq.com";
          };
          core = {
            autocrlf = "input";
            excludesfile = "~/.gitignore_global";
          };
        };
      };

      home.file.".gitignore_global".text = ''
        .DS_Store
        *~
        .direnv/
      '';
    }

    (lib.mkIf isDarwin {
      # These are the original Mac files, copied byte-for-byte into the
      # repository. Nix owns their placement but not their contents.
      home.file = {
        ".zshrc".source = dotfiles + "/zshrc";
        ".zprofile".source = dotfiles + "/zprofile";
        ".zshenv".source = dotfiles + "/zshenv";
      };

      xdg.configFile = {
        "nvim/init.lua".source = dotfiles + "/nvim-init.lua";
        "wezterm/wezterm.lua".source = dotfiles + "/wezterm.lua";
        "starship.toml".source = dotfiles + "/starship.toml";
        "aerospace/aerospace.toml".source = dotfiles + "/aerospace.toml";
        "ghostty/config".source = dotfiles + "/ghostty.conf";
      };

      # Install the commands referenced by the original dotfiles. Their
      # configuration remains the exact source files above.
      home.packages = with pkgs; [
        direnv
        eza
        neovim
        starship
        zsh-autosuggestions
        zsh-syntax-highlighting
      ];
    })

    (lib.mkIf (!isDarwin) {
      # Servers share the portable parts, without Mac/Homebrew paths.
      programs.zsh = {
        enable = true;
        autosuggestion.enable = true;
        syntaxHighlighting.enable = true;
        shellAliases = {
          e = "nvim";
          ls = "eza --icons";
        };
        initContent = ''
          proxy() {
            export http_proxy="http://127.0.0.1:7892"
            export https_proxy="$http_proxy"
            export all_proxy="socks5://127.0.0.1:7892"
            export HTTP_PROXY="$http_proxy"
            export HTTPS_PROXY="$https_proxy"
            export ALL_PROXY="$all_proxy"
          }

          unproxy() {
            unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
          }
        '';
      };

      programs.starship = {
        enable = true;
        enableZshIntegration = true;
      };

      programs.direnv = {
        enable = true;
        enableZshIntegration = true;
        nix-direnv.enable = true;
      };
    })
  ]
