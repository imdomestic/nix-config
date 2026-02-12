{
  inputs,
  pkgs,
  lib,
  system,
  username,
  ...
}: {
  home.packages = with pkgs; [
    zoxide
    curl
    wireguard-tools
    just
    tmux
    bat
    neofetch
    fastfetch
    ripgrep
    fd
    eza
    duf
    btop
    zinit
    nix-output-monitor
    tree
    file
    iperf3
    which
    wget

    # archives
    zip
    xz
    unzip
    p7zip
    zstd
  ];

  programs.yazi = {
    enable = true;
    settings = {
      theme = {
        flavor = {
          dark = "kanso-ink";
          light = "kanso-pearl";
        };
      };
    };
    flavors = {
      kanso-ink = ../modules/yazi/kanso-ink.yazi;
      kanso-pearl = ../modules/yazi/kanso-pearl.yazi;
    };
  };

  programs.zsh = {
    enable = true;
  };

  programs.nushell = {
    enable = true;
    shellAliases = {
      # --- JJ (Jujutsu) ---
      jdesc = "jj desc";
      jn = "jj new";
      jst = "jj st";
      jl = "jj log";
      jc = "jj commit";
      ja = "jj abandon";
      jsq = "jj squash";
      jd = "jj diff";
      je = "jj edit";
      jne = "jj next";
      jgi = "jj git init";
      jgp = "jj git push";
      jgf = "jj git fetch";
      jgcl = "jj git clone --colocate";

      # --- Neovim / Editors ---
      nvimdiff = "nvim -d";
      lg = "lazygit";
      kvim = "NVIM_APPNAME=kvim nvim";
      hvim = "NVIM_APPNAME=hvim nvim";
      lvim = "NVIM_APPNAME=lazyvim nvim";
      dvim = "NVIM_APPNAME=dvim nvim";
      ra = "joshuto";
      nvid = "neovide --frame buttonless --title-hidden";

      c = "clear";
      q = "exit";

      # --- File Ops ---
      mkdir = "mkdir -p";
      fm = "ranger";
      ls = "eza --color=auto --icons";
      l = "ls -l";
      la = "ls -a";
      lla = "ls -la";
      lt = "ls --tree";
      cat = "bat --color always --plain";
      # Nu 的 cp/mv/rm 默认行为略有不同，但这些参数通常兼容
      mv = "mv -v";
      cp = "cp -vr";
      rm = "rm -vr";

      # --- Git (基础部分) ---
      # 复杂 Git 别名建议使用 git config alias 或 def，这里保留通用的
      g = "git";
      ga = "git add";
      gaa = "git add --all";
      gb = "git branch";
      gbD = "git branch -D";
      gba = "git branch -a";
      gbd = "git branch -d";
      gc = "git commit -v";
      "gc!" = "git commit -v --amend";
      gca = "git commit -v -a";
      "gca!" = "git commit -v -a --amend";
      gcam = "git commit -a -m";
      gco = "git checkout";
      gcl = "git clone";
      gd = "git diff";
      gf = "git fetch";
      gl = "git pull";
      gp = "git push"; # 覆盖了你原来的 p 别名，原来的 p 逻辑太复杂，见下文 def
      gss = "git status -s";
      gst = "git status";
      gsw = "git switch";
    };
    extraConfig = ''
      $env.config.show_banner = false
      $env.config.ls.use_ls_colors = true
      $env.config.table.mode = "rounded"

      $env.config.history = {
          file_format: "sqlite"
          max_size: 100_000
          sync_on_enter: true
          isolation: false
      }

      $env.config.keybindings = (
        $env.config.keybindings | append [
          {
            name: fzf_history
            modifier: control
            keycode: char_r
            mode: [emacs, vi_normal, vi_insert]
            event: {
              send: executehostcommand
              cmd: "history | get command | reverse | uniq | to text | fzf --layout=reverse --height=40% | decode utf-8 | str trim | commandline edit --replace $in"
            }
          }

          {
            name: fzf_files
            modifier: control
            keycode: char_t
            mode: [emacs, vi_normal, vi_insert]
            event: {
              send: executehostcommand
              cmd: "fd --type f --hidden --exclude .git | fzf --layout=reverse | decode utf-8 | str trim | commandline edit --insert $in"
            }
          }
        ]
      )

      $env.config.completions.external = {
       enable: true
       max_results: 100
      }

      def p [msg: string = "update"] {
          git add .
          git commit -am $msg
          git push -u origin main
      }
    '';
    extraEnv = ''
      # $env.PATH = ($env.PATH | split row (char esep) | prepend '~/.cargo/bin')
    '';
  };

  programs.carapace = {
    enable = true;
    enableNushellIntegration = true;
  };

  programs.fzf = {
    enable = true;
    defaultOptions = ["--height 40%" "--layout=reverse" "--border"];
  };

  programs.zoxide = {
    enable = true;
    enableNushellIntegration = true;
    # 关键配置：把 cd 命令直接替换成 zoxide
    # 这样你还是习惯敲 cd，但拥有了 zoxide 的所有超能力
    # options = ["--cmd cd"];
  };

  programs.tmux = {
    enable = true;
    terminal = "tmux-256color";
    mouse = true;
    plugins = [pkgs.tmuxPlugins.dotbar];
    extraConfig = ''
      set-option -ga terminal-overrides ",*256col*:Tc"

      setw -g xterm-keys on
      set -s escape-time 0
      set -sg repeat-time 300
      set -s focus-events on
      set -sg exit-empty on

      set -q -g status-utf8 on
      setw -q -g utf8 on

      set -g visual-activity off
      setw -g monitor-activity off
      setw -g monitor-bell off
      set -g history-limit 10000
      set -g set-clipboard on

      set-option -g renumber-windows on
      set -g base-index 1
      setw -g pane-base-index 1

      bind r source-file ~/.config/tmux/tmux.conf \; display '~/.config/tmux/tmux.conf sourced'
      bind > swap-pane -D
      bind < swap-pane -U
      bind | swap-pane

      bind -r H resize-pane -L 5
      bind -r J resize-pane -D 5
      bind -r K resize-pane -U 5
      bind -r L resize-pane -R 5
    '';
  };

  xdg.configFile = {
    nvim.source = inputs.hvim.outPath;
  };

  programs.neovim = {
    enable = true;
    defaultEditor = true;
  };

  programs.nh = {
    enable = true;
    clean.enable = false;
    clean.extraArgs = "--keep-since 4d --keep 3";
    flake =
      if lib.hasInfix "linux" system
      then "/home/${username}/.config/nix-config"
      else "/Users/${username}/.config/nix-config";
  };
}
