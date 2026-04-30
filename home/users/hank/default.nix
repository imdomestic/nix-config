{
  lib,
  inputs,
  username,
  system,
  pkgs,
  pkgs-unstable,
  ...
}: let
  zjstatus = pkgs.fetchurl {
    url = "https://github.com/dj95/zjstatus/releases/download/v0.22.0/zjstatus.wasm";
    sha256 = "sha256-TeQm0gscv4YScuknrutbSdksF/Diu50XP4W/fwFU3VM=";
  };
in {
  imports = [
    # ../../modules/zsh
  ];

  programs.git = {
    enable = true;
    settings = {
      user.name = "Hank Hogan";
      user.email = "ysh2291939848@outlook.com";
      push.autoSetupRemote = true;
      gpg.format = "ssh";
      user.signingkey = "~/.ssh/id_ed25519.pub";
      commit.gpgsign = true;
      column.ui = "auto";
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
    enableZshIntegration = false;
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

  programs.zsh = {
    enableCompletion = true;
    autocd = true;
    defaultKeymap = "viins";

    autosuggestion = {
      enable = true;
      highlight = "fg=#585B70,bold";
    };

    historySubstringSearch.enable = true;

    syntaxHighlighting = {
      enable = true;
      highlighters = ["main" "brackets" "pattern" "cursor" "regexp" "root" "line"];
    };

    history = {
      size = 10000;
      save = 10000;
      path = "$HOME/.cache/zsh/.zhistory";
      share = true;
      extended = true;
      ignoreSpace = true;
      ignoreAllDups = true;
      saveNoDups = true;
      expireDuplicatesFirst = true;
    };

    setOptions = [
      "AUTO_MENU"
      "AUTO_PARAM_SLASH"
      "COMPLETE_IN_WORD"
      "NO_MENU_COMPLETE"
      "HASH_LIST_ALL"
      "ALWAYS_TO_END"
      "NOTIFY"
      "NOHUP"
      "MAILWARN"
      "INTERACTIVE_COMMENTS"
      "NOBEEP"
      "HIST_NO_FUNCTIONS"
      "HIST_REDUCE_BLANKS"
      "NO_FLOW_CONTROL"
      "NO_NOMATCH"
      "NO_CORRECT"
      "NO_EQUALS"
    ];

    plugins = [
      {
        name = "zsh-autopair";
        src = pkgs.zsh-autopair;
        file = "share/zsh/zsh-autopair/autopair.zsh";
      }
      {
        name = "zsh-you-should-use";
        src = pkgs.zsh-you-should-use;
        file = "share/zsh/plugins/you-should-use/you-should-use.plugin.zsh";
      }
      {
        name = "fzf-tab";
        src = pkgs.zsh-fzf-tab;
        file = "share/fzf-tab/fzf-tab.plugin.zsh";
      }
      {
        name = "zsh-history-search-multi-word";
        src = pkgs.zsh-history-search-multi-word;
        file = "share/zsh/zsh-history-search-multi-word/history-search-multi-word.plugin.zsh";
      }
    ];

    shellAliases = {
      # jj (jujutsu)
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

      # editors
      nvimdiff = "nvim -d";
      p = "git add . && git commit -am 'update' && git push -u origin main";
      getidf = "source ~/esp/esp-idf/export.sh";
      brew86 = "arch -x86_64 /usr/local/homebrew/bin/brew";
      lg = "lazygit";
      kvim = "NVIM_APPNAME=kvim nvim";
      hvim = "NVIM_APPNAME=hvim nvim";
      lvim = "NVIM_APPNAME=lazyvim nvim";
      dvim = "NVIM_APPNAME=dvim nvim";
      ra = "joshuto";
      nvid = "neovide --frame buttonless --title-hidden";

      # general
      settings = "gnome-control-center";
      run = "pnpm run";
      c = "clear";
      q = "exit";
      cleanram = "sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'";
      trim_all = "sudo fstrim -va";
      mkgrub = "sudo grub-mkconfig -o /boot/grub/grub.cfg";
      mtar = "tar -zcvf";
      utar = "tar -zxvf";
      uz = "unzip";
      ".." = "cd ..";
      psg = "ps aux | grep -v grep | grep -i -e VSZ -e";
      mkdir = "mkdir -p";
      fm = "ranger";

      # pacman / paru
      pacin = ''pacman -Slq | fzf -m --preview 'cat <(pacman -Si {1}) <(pacman -Fl {1} | awk "{print $2}")' | xargs -ro sudo pacman -S'';
      paruin = ''paru -Slq | fzf -m --preview 'cat <(paru -Si {1}) <(paru -Fl {1} | awk "{print $2}")' | xargs -ro paru -S'';
      pacrem = ''pacman -Qq | fzf --multi --preview 'pacman -Qi {1}' | xargs -ro sudo pacman -Rns'';
      pac = "pacman -Q | fzf";
      parucom = "paru -Gc";
      parupd = "paru -Qua";
      pacupd = "pacman -Qu";
      parucheck = "paru -Gp";
      cleanpac = "sudo pacman -Rns $(pacman -Qtdq); paru -c";
      installed = "grep -i installed /var/log/pacman.log";

      # file operations
      ls = "eza --color=auto --icons";
      l = "ls -l";
      la = "ls -a";
      lla = "ls -la";
      lt = "ls --tree";
      cat = "bat --color always --plain";
      grep = "grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn,.idea,.tox}";
      mv = "mv -v";
      cp = "cp -vr";
      rm = "rm -vr";

      # git basics
      commit = "git add . && git commit -m";
      push = "git push";
      git-rm = "git ls-files --deleted -z | xargs -0 git rm";
      g = "git";
      ga = "git add";
      gaa = "git add --all";
      gam = "git am";
      gama = "git am --abort";
      gamc = "git am --continue";
      gams = "git am --skip";
      gamscp = "git am --show-current-patch";
      gap = "git apply";
      gapa = "git add --patch";
      gapt = "git apply --3way";
      gau = "git add --update";
      gav = "git add --verbose";

      # git branch
      gb = "git branch";
      gbD = "git branch -D";
      gba = "git branch -a";
      gbd = "git branch -d";
      gbda = ''git branch --no-color --merged | command grep -vE "^([+*]|\s*($(git_main_branch)|$(git_develop_branch))\s*$)" | command xargs git branch -d 2>/dev/null'';
      gbl = "git blame -b -w";
      gbnm = "git branch --no-merged";
      gbr = "git branch --remote";

      # git bisect
      gbs = "git bisect";
      gbsb = "git bisect bad";
      gbsg = "git bisect good";
      gbsr = "git bisect reset";
      gbss = "git bisect start";

      # git commit
      gc = "git commit -v";
      "gc!" = "git commit -v --amend";
      gca = "git commit -v -a";
      "gca!" = "git commit -v -a --amend";
      gcam = "git commit -a -m";
      "gcan!" = "git commit -v -a --no-edit --amend";
      "gcans!" = "git commit -v -a -s --no-edit --amend";
      gcas = "git commit -a -s";
      gcasm = "git commit -a -s -m";
      gcmsg = "git commit -m";
      "gcn!" = "git commit -v --no-edit --amend";
      gcs = "git commit -S";
      gcsm = "git commit -s -m";
      gcss = "git commit -S -s";
      gcssm = "git commit -S -s -m";

      # git checkout
      gcb = "git checkout -b";
      gcd = "git checkout $(git_develop_branch)";
      gcf = "git config --list";
      gcl = "git clone";
      gcld = "git clone --depth";
      gclr = "git clone --recurse-submodules";
      gclean = "git clean -id";
      gcm = "git checkout $(git_main_branch)";
      gco = "git checkout";
      gcor = "git checkout --recurse-submodules";
      gcount = "git shortlog -sn";

      # git cherry-pick
      gcp = "git cherry-pick";
      gcpa = "git cherry-pick --abort";
      gcpc = "git cherry-pick --continue";

      # git diff
      gd = "git diff";
      gdca = "git diff --cached";
      gdct = "git describe --tags $(git rev-list --tags --max-count=1)";
      gdcw = "git diff --cached --word-diff";
      gds = "git diff --staged";
      gdt = "git diff-tree --no-commit-id --name-only -r";
      gdup = "git diff @{upstream}";
      gdw = "git diff --word-diff";

      # git fetch
      gf = "git fetch";
      gfa = "git fetch --all --prune --jobs=10";
      gfg = "git ls-files | grep";
      gfo = "git fetch origin";

      # git gui
      gg = "git gui citool";
      gga = "git gui citool --amend";

      # git pull/push
      ggpull = ''git pull origin "$(git_current_branch)"'';
      ggpur = "ggu";
      ggpush = ''git push origin "$(git_current_branch)"'';
      ggsup = "git branch --set-upstream-to=origin/$(git_current_branch)";
      ghh = "git help";
      gl = "git pull";
      gp = "git push";
      gpd = "git push --dry-run";
      gpf = "git push --force-with-lease";
      "gpf!" = "git push --force";
      gpoat = "git push origin --all && git push origin --tags";
      gpr = "git pull --rebase";
      gpristine = "git reset --hard && git clean -dffx";
      gpsup = "git push --set-upstream origin $(git_current_branch)";
      gpu = "git push upstream";
      gpv = "git push -v";
      gup = "git pull --rebase";
      gupa = "git pull --rebase --autostash";
      gupav = "git pull --rebase --autostash -v";
      gupv = "git pull --rebase -v";
      glum = "git pull upstream $(git_main_branch)";

      # git ignore
      gignore = "git update-index --assume-unchanged";
      gignored = ''git ls-files -v | grep "^[[:lower:]]"'';
      gunignore = "git update-index --no-assume-unchanged";

      # git log
      glg = "git log --stat";
      glgg = "git log --graph";
      glgga = "git log --graph --decorate --all";
      glgm = "git log --graph --max-count=10";
      glgp = "git log --stat -p";
      glo = "git log --oneline --decorate";
      globurl = "noglob urlglobber ";
      glod = "git log --graph --pretty='%Cred%h%Creset -%C(auto)%d%Creset %s %Cgreen(%ad) %C(bold blue)<%an>%Creset'";
      glods = "git log --graph --pretty='%Cred%h%Creset -%C(auto)%d%Creset %s %Cgreen(%ad) %C(bold blue)<%an>%Creset' --date=short";
      glog = "git log --oneline --decorate --graph";
      gloga = "git log --oneline --decorate --graph --all";
      glol = "git log --graph --pretty='%Cred%h%Creset -%C(auto)%d%Creset %s %Cgreen(%ar) %C(bold blue)<%an>%Creset'";
      glola = "git log --graph --pretty='%Cred%h%Creset -%C(auto)%d%Creset %s %Cgreen(%ar) %C(bold blue)<%an>%Creset' --all";
      glols = "git log --graph --pretty='%Cred%h%Creset -%C(auto)%d%Creset %s %Cgreen(%ar) %C(bold blue)<%an>%Creset' --stat";
      glp = "_git_log_prettily";

      # git merge
      gm = "git merge";
      gma = "git merge --abort";
      gmom = "git merge origin/$(git_main_branch)";
      gmtl = "git mergetool --no-prompt";
      gmtlvim = "git mergetool --no-prompt --tool=vimdiff";
      gmum = "git merge upstream/$(git_main_branch)";

      # git rebase
      grb = "git rebase";
      grba = "git rebase --abort";
      grbc = "git rebase --continue";
      grbd = "git rebase $(git_develop_branch)";
      grbi = "git rebase -i";
      grbm = "git rebase $(git_main_branch)";
      grbo = "git rebase --onto";
      grbom = "git rebase origin/$(git_main_branch)";
      grbs = "git rebase --skip";

      # git remote
      gr = "git remote";
      gra = "git remote add";
      grmv = "git remote rename";
      grrm = "git remote remove";
      grset = "git remote set-url";
      grup = "git remote update";
      grv = "git remote -v";

      # git reset/restore
      grh = "git reset";
      grhh = "git reset --hard";
      groh = "git reset origin/$(git_current_branch) --hard";
      grs = "git restore";
      grss = "git restore --source";
      grst = "git restore --staged";
      gru = "git reset --";

      # git rm
      grm = "git rm";
      grmc = "git rm --cached";
      grwh = "git rm --cached $(git ls-files -i -c --exclude-from=.gitignore)";
      grwhx = "git ls-files -i -c --exclude-from=.gitignore | xargs git rm --cached";
      grad = "git rm -r --cached . && git add .";

      # git show/status
      gsh = "git show";
      gsps = "git show --pretty=short --show-signature";
      gsb = "git status -sb";
      gss = "git status -s";
      gst = "git status";

      # git stash
      gsta = "git stash push";
      gstaa = "git stash apply";
      gstall = "git stash --all";
      gstc = "git stash clear";
      gstd = "git stash drop";
      gstl = "git stash list";
      gstp = "git stash pop";
      gsts = "git stash show --text";
      gstu = "gsta --include-untracked";

      # git submodule
      gsi = "git submodule init";
      gsu = "git submodule update";

      # git switch
      gsw = "git switch";
      gswc = "git switch -c";
      gswd = "git switch $(git_develop_branch)";
      gswm = "git switch $(git_main_branch)";

      # git svn
      gsd = "git svn dcommit";
      gsr = "git svn rebase";
      git-svn-dcommit-push = "git svn dcommit && git push github $(git_main_branch):svntrunk";

      # git tag
      gtl = "noglob _gtl";
      gts = "git tag -s";
      gtv = "git tag | sort -V";

      # git misc
      grt = ''cd "$(git rev-parse --show-toplevel || echo .)"'';
      grev = "git revert";
      gk = "\\gitk --all --branches &!";
      gke = "\\gitk --all $(git log -g --pretty=%h) &!";
      gwch = "git whatchanged -p --abbrev-commit --pretty=medium";
      gwip = ''git add -A; git rm $(git ls-files --deleted) 2> /dev/null; git commit --no-verify --no-gpg-sign -m "--wip-- [skip ci]"'';
      gunwip = ''git log -n 1 | grep -q -c "\-\-wip\-\-" && git reset HEAD~1'';
    };

    envExtra = ''
      export PATH="$HOME/.moon/bin:$PATH"
      export PATH="$HOME/.ghcup/bin:$PATH"
      export PATH="$HOME/.local/bin:$PATH"
      export PATH="$HOME/.cargo/bin:$PATH"

      export KUBECONFIG="$HOME/.config/k3s.yaml"
      export TERMINAL="ghostty"

      export XDG_CONFIG_HOME="$HOME/.config"
      export XDG_CACHE_HOME="$HOME/.cache"
      export XDG_DATA_HOME="$HOME/.local/share"
      export XDG_STATE_HOME="$HOME/.local/state"
    '';

    initContent = lib.mkMerge [
      (lib.mkBefore ''
        ZSH_AUTOSUGGEST_USE_ASYNC="true"
      '')
      (lib.mkOrder 550 ''
        zmodload zsh/zle
        zmodload zsh/zpty
        zmodload zsh/complist
      '')
      ''
        ${builtins.readFile ./init-extra.zsh}
      ''
    ];
  };

  programs.carapace = {
    enable = true;
    enableNushellIntegration = true;
    enableZshIntegration = true;
  };

  programs.emacs = {
    enable = false;
  };

  programs.starship = {
    enable = true;
    enableTransience = true;
    enableZshIntegration = true;
  };

  xdg.configFile = {
    kvim.source = inputs.kvim.outPath;
    wezterm.source = inputs.wezterm-config.outPath;
    neofetch = {
      source = ../../modules/neofetch;
      recursive = true;
    };
    "starship.toml" = {
      source = ../../modules/starship/starship.toml;
    };
  };


  home.file.".local/share/fonts/Recursive-Bold.ttf".source = ../../../fonts/Recursive-Bold.ttf;
  home.file.".local/share/fonts/Recursive-Italic.ttf".source = ../../../fonts/Recursive-Italic.ttf;
  home.file.".local/share/fonts/Recursive-Regular.ttf".source = ../../../fonts/Recursive-Regular.ttf;
  # home.file.wallpapers.source = ../../../wallpapers;

  home.packages = [pkgs.zsh-completions];
}
