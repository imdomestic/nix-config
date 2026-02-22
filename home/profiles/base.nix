{
  inputs,
  pkgs,
  lib,
  system,
  username,
  ...
}: let
  zjstatus = pkgs.fetchurl {
    url = "https://github.com/dj95/zjstatus/releases/download/v0.22.0/zjstatus.wasm";
    sha256 = "sha256-TeQm0gscv4YScuknrutbSdksF/Diu50XP4W/fwFU3VM=";
  };
in {
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
    sops

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
      # mkdir = "mkdir -p";
      # fm = "ranger";
      # ls = "eza --color=auto --icons";
      # l = "ls -l";
      # la = "ls -a";
      # lla = "ls -la";
      # lt = "ls --tree";
      # cat = "bat --color always --plain";
      # Nu 的 cp/mv/rm 默认行为略有不同，但这些参数通常兼容
      # mv = "mv -v";
      # cp = "cp -vr";
      # rm = "rm -vr";

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
    # options = ["--cmd cd"];
  };

  programs.tmux = {
    enable = true;
    terminal = "tmux-256color";
    mouse = true;
    plugins = with pkgs.tmuxPlugins; [
      dotbar
      {
        plugin = resurrect;
        extraConfig = ''
          # set -g @resurrect-strategy-nvim 'session'
          set -g @resurrect-capture-pane-contents 'on'
        '';
      }
      {
        plugin = continuum;
        extraConfig = ''
          # Tmux 启动时自动恢复最后一次保存的会话
          set -g @continuum-restore 'on'
          # 每 15 分钟自动在后台保存一次（默认也是 15）
          set -g @continuum-save-interval '15'
        '';
      }
    ];
    extraConfig = ''
      set-option -ga terminal-overrides ",*256col*:Tc"
      set -ga terminal-overrides ',*:Ss=\E[%p1%d q:Se=\E[6 q'

      set -g allow-passthrough on
      set -ga update-environment TERM
      set -ga update-environment TERM_PROGRAM

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

      set -g prefix C-b
      bind C-b send-prefix
      bind -r H resize-pane -L 5
      bind -r J resize-pane -D 5
      bind -r K resize-pane -U 5
      bind -r L resize-pane -R 5

      setw -g mode-keys vi
      bind -T copy-mode-vi v send-keys -X begin-selection
      bind -T copy-mode-vi y send-keys -X copy-selection-and-cancel
    '';
  };

  programs.zellij = {
    enable = true;
    enableZshIntegration = true;
    settings = {
      theme = "evergarden-fall";
      themes = {
        evergarden-fall = {
          text_unselected = {
            base = [248 249 232]; # text
            background = [35 42 46]; # base
            emphasis_0 = [248 249 232]; # text
            emphasis_1 = [173 201 188]; # subtext1
            emphasis_2 = [150 180 170]; # subtext0
            emphasis_3 = [131 158 154]; # overlay2
          };
          text_selected = {
            base = [248 249 232]; # text
            background = [55 65 69]; # surface1
            emphasis_0 = [255 255 255]; # white
            emphasis_1 = [178 202 237]; # blue
            emphasis_2 = [179 230 219]; # skye
            emphasis_3 = [179 217 230]; # snow
          };
          ribbon_selected = {
            base = [35 42 46]; # base
            background = [179 230 219]; # skye
            emphasis_0 = [35 42 46]; # base
            emphasis_1 = [43 50 55]; # surface0
            emphasis_2 = [55 65 69]; # surface1
            emphasis_3 = [74 88 92]; # surface2
          };
          ribbon_unselected = {
            base = [150 180 170]; # subtext0
            background = [43 50 55]; # surface0
            emphasis_0 = [173 201 188]; # subtext1
            emphasis_1 = [150 180 170]; # subtext0
            emphasis_2 = [131 158 154]; # overlay2
            emphasis_3 = [111 135 136]; # overlay1
          };
          table_title = {
            base = [248 249 232]; # text
            background = [35 42 46]; # base
            emphasis_0 = [179 230 219]; # skye
            emphasis_1 = [178 202 237]; # blue
            emphasis_2 = [219 230 175]; # lime
            emphasis_3 = [203 227 179]; # green
          };
          table_cell_selected = {
            base = [248 249 232]; # text
            background = [55 65 69]; # surface1
            emphasis_0 = [179 230 219]; # skye
            emphasis_1 = [178 202 237]; # blue
            emphasis_2 = [219 230 175]; # lime
            emphasis_3 = [203 227 179]; # green
          };
          table_cell_unselected = {
            base = [150 180 170]; # subtext0
            background = [35 42 46]; # base
            emphasis_0 = [131 158 154]; # overlay2
            emphasis_1 = [111 135 136]; # overlay1
            emphasis_2 = [88 104 109]; # overlay0
            emphasis_3 = [74 88 92]; # surface2
          };
          list_selected = {
            base = [248 249 232]; # text
            background = [55 65 69]; # surface1
            emphasis_0 = [179 230 219]; # skye
            emphasis_1 = [178 202 237]; # blue
            emphasis_2 = [210 191 243]; # purple
            emphasis_3 = [243 192 229]; # pink
          };
          list_unselected = {
            base = [150 180 170]; # subtext0
            background = [35 42 46]; # base
            emphasis_0 = [173 201 188]; # subtext1
            emphasis_1 = [150 180 170]; # subtext0
            emphasis_2 = [131 158 154]; # overlay2
            emphasis_3 = [111 135 136]; # overlay1
          };
          frame_selected = {
            base = [179 230 219]; # skye
            background = [55 65 69]; # surface1
            emphasis_0 = [178 202 237]; # blue
            emphasis_1 = [203 227 179]; # green
            emphasis_2 = [245 208 152]; # yellow
            emphasis_3 = [247 161 130]; # orange
          };
          frame_highlight = {
            base = [245 208 152]; # yellow
            background = [55 65 69]; # surface1
            emphasis_0 = [247 161 130]; # orange
            emphasis_1 = [245 127 130]; # red
            emphasis_2 = [243 192 229]; # pink
            emphasis_3 = [210 191 243]; # purple
          };
          exit_code_success = {
            base = [203 227 179]; # green
            background = [35 42 46]; # base
            emphasis_0 = [179 227 202]; # aqua
            emphasis_1 = [203 227 179]; # green
            emphasis_2 = [219 230 175]; # lime
            emphasis_3 = [179 230 219]; # skye
          };
          exit_code_error = {
            base = [245 127 130]; # red
            background = [35 42 46]; # base
            emphasis_0 = [200 80 85]; # darker red
            emphasis_1 = [245 127 130]; # red
            emphasis_2 = [247 161 130]; # orange
            emphasis_3 = [245 208 152]; # yellow
          };
          multiplayer_user_colors = {
            user_0 = [179 230 219]; # skye
            user_1 = [203 227 179]; # green
            user_2 = [178 202 237]; # blue
            user_3 = [210 191 243]; # purple
            user_4 = [245 208 152]; # yellow
            user_5 = [247 161 130]; # orange
            user_6 = [243 192 229]; # pink
            user_7 = [179 227 202]; # aqua
            user_8 = [245 127 130]; # red
            user_9 = [246 206 229]; # cherry
          };
        };
      };
      pane_frames = false;
      default_layout = "evergarden_bottom";
      show_startup_tips = false;
    };
  };

  xdg.configFile = {
    hvim.source = inputs.hvim.outPath;
    "zellij/layouts/evergarden_bottom.kdl".text = ''
      layout {
        pane split_direction="vertical" {
          pane
        }

        pane size=1 borderless=true {
          plugin location="file:${zjstatus}" {
            color_bg0   "#232a2e" // Hard background (Base)
            color_bg1   "#2d353b" // Medium background (Surface) - Main Bar BG
            color_bg2   "#3d484d" // Soft background

            color_fg0   "#d3c6aa" // Main Text (Beige)
            color_fg1   "#9da9a0" // Dimmed Text

            color_love      "#e67e80" // Red
            color_gold      "#dbbc7f" // Yellow
            color_rose      "#e69875" // Orange
            color_pine      "#7fbbb3" // Blue
            color_foam      "#a7c080" // Green
            color_iris      "#d699b6" // Purple

            color_orange    "#e69875"
            color_muted     "#5e6c70"
            color_subtle    "#859289"

            format_left   "#[bg=$bg0,fg=$fg0,bold] {session} {mode}#[]"
            format_center "{tabs}"
            // format_right  "#[fg=$fg1]{datetime}"
            format_space  "#[bg=$bg0]"
            format_hide_on_overlength "true"
            format_precedence "lrc"

            border_enabled  "false"
            border_char     "─"
            border_format   "#[fg=$bg2]{char}"
            border_position "top"

            hide_frame_for_single_pane "true"

            mode_normal        "#[bg=$bg0,fg=$foam,bold] NORMAL "
            mode_locked        "#[bg=$bg0,fg=$muted] LOCKED "
            mode_pane          "#[bg=$bg0,fg=$pine,bold] PANE "
            mode_tab           "#[bg=$bg0,fg=$rose,bold] TAB "
            mode_scroll        "#[bg=$bg0,fg=$fg0,bold] SCROLL "
            mode_enter_search  "#[bg=$bg0,fg=$fg0,bold] ENT-SEARCH "
            mode_search        "#[bg=$bg0,fg=$subtle,bold] SEARCH "
            mode_resize        "#[bg=$bg0,fg=$gold,bold] RESIZE "
            mode_rename_tab    "#[bg=$bg0,fg=$gold,bold] RENAME TAB "
            mode_rename_pane   "#[bg=$bg0,fg=$gold,bold] RENAME PANE "
            mode_move          "#[bg=$bg0,fg=$gold,bold] MOVE "
            mode_session       "#[bg=$bg0,fg=$love,bold] SESSION "
            mode_prompt        "#[bg=$bg0,fg=$love,bold] PROMPT "
            mode_tmux          "#[bg=$bg0,fg=$gold,bold] TMUX "

            tab_normal              "#[bg=$bg1,fg=$subtle] {index} {name} {floating_indicator}"
            tab_normal_fullscreen   "#[bg=$bg1,fg=$subtle] {index} {name} {fullscreen_indicator}"
            tab_normal_sync         "#[bg=$bg1,fg=$subtle] {index} {name} {sync_indicator}"

            tab_active              "#[bg=$bg2,fg=$fg0,bold] {index} {name} {floating_indicator}"
            tab_active_fullscreen   "#[bg=$bg2,fg=$fg0,bold] {index} {name} {fullscreen_indicator}"
            tab_active_sync         "#[bg=$bg2,fg=$fg0,bold] {index} {name} {sync_indicator}"

            tab_separator           ""

            tab_sync_indicator       ""
            tab_fullscreen_indicator "󰊓"
            tab_floating_indicator   "󰹙"

            notification_format_unread "#[bg=$orange,fg=$bg0]  #[bg=$orange,fg=$bg0] {message} #[bg=$bg1,fg=$orange] "
            notification_format_no_notifications ""
            notification_show_interval "10"

            datetime          "{format}"
            datetime_format   "%Y-%m-%d %H:%M"
            datetime_timezone "Asia/Shanghai"
          }
        }
      }
    '';
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
