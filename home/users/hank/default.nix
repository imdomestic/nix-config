{
  config,
  lib,
  inputs,
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
    # 精简版 nixvim(nix 支持常开);dev.nix 会把 my.nixvim.dev.enable 打开
    ../../modules/nixvim
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
      diff.tool = "nvimdiff";
      difftool.prompt = false;
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
    clock24 = true;
    keyMode = "vi";
    plugins = with pkgs.tmuxPlugins; [
      {
        plugin = dotbar;
        # dotbar 是 run-shell 时把 @tmux-dotbar-* 读成普通字符串、烤进
        # window-status-format 的,所以这些 set 必须排在插件加载**之前**。
        # home-manager 正好把插件自己的 extraConfig 放在它的 run-shell 前面
        # (modules/programs/tmux.nix);而 programs.tmux.extraConfig 是 mkAfter,
        # 排在所有插件后面 —— 写在那儿就晚了,dotbar 已经读完了。
        #
        # #{@agent_state} 是 window 级 user option,状态栏对每个 window 单独展开
        # 格式串,没设的窗口展开成空串,渲染和现在一模一样。写它的是
        # ~/.claude/tmux-agent-status.sh。
        #
        # 只改了非 ssh 那条分支:dotbar 检测到 pane_current_command 是 ssh 时会换
        # 成自己的 ssh 格式串,那种窗口不带标记。跑本地 agent 不受影响。
        extraConfig = ''
          set -g @tmux-dotbar-window-status-format ' #W#{@agent_state} '

          # 右半边默认是关的(@tmux-dotbar-right false),打开后 dotbar 会渲染
          # time_component —— 而 -status-right-text 正是塞进那个组件里的文本,
          # 所以走这个选项就能白拿它的配色,不用自己硬写 #[bg=...,fg=...]。
          # (直接覆盖 @tmux-dotbar-status-right 的话样式得自己重写一遍。)
          #
          # host_short 是 **跑 tmux server 的那台机器**。和 dotbar 自带的 ssh 窗口
          # 名正好互补:窗口列表告诉你每个窗口 ssh 到了哪儿(它会去 pane_title 里
          # 抠 host),右下角告诉你这个 tmux 本身在哪台机器上。
          # 所以 `ssh 过去再开 tmux` 和 `本地 tmux 里 ssh` 两种用法都不会认错机器。
          set -g @tmux-dotbar-right true
          set -g @tmux-dotbar-status-right-text ' #{host_short} '
        '';
      }
      # {
      #   plugin = continuum;
      #   extraConfig = ''
      #     # Tmux 启动时自动恢复最后一次保存的会话
      #     set -g @continuum-restore 'on'
      #     # 每 15 分钟自动在后台保存一次（默认也是 15）
      #     set -g @continuum-save-interval '15'
      #   '';
      # }

      # 存/取整个会话布局。**手动**:prefix C-s 存,prefix C-r 取。
      #
      # 故意不带 continuum:那个每 15 分钟自动存 + tmux 启动时自动恢复,代价是
      # 你开一个新 tmux 就会被塞回上次的布局。要自动化随时把下面这段注释解开:
      #   { plugin = continuum; extraConfig = ''
      #       set -g @continuum-restore 'on'
      #       set -g @continuum-save-interval '15'
      #     ''; }
      #
      # 没写 @resurrect-strategy-nvim 'session':那个只在 pane 目录下存在
      # Session.vim 时才有用(要靠 vim-obsession 之类维护),这边的 nixvim 没有,
      # 写了也是空转。
      {
        plugin = resurrect;
        extraConfig = ''
          set -g @resurrect-capture-pane-contents 'on'
        '';
      }

      # vimium 式的提示复制:按 prefix Space,屏幕上所有路径 / URL / git SHA /
      # IP / UUID / docker 镜像 / 十六进制色值旁边浮出字母提示,按字母就进
      # 剪贴板 —— 不进 copy-mode、不用移动光标。
      #
      # 占掉了默认的 `prefix Space`(next-layout)。真要切布局还有 `prefix M-1`
      # 到 `M-7` 直接选。
      {
        plugin = tmux-thumbs;
        extraConfig = ''
          set -g @thumbs-key space
          # 相同文本共用一个提示,省字母(默认 disabled)
          set -g @thumbs-unique enabled
          # 提示从靠近光标处开始编号,常用的落在单字母上(默认 disabled)
          set -g @thumbs-reverse enabled
        '';
      }
    ];
    extraConfig = ''
      set-option -ga terminal-overrides ",*256col*:Tc"
      set -ga terminal-overrides ',*:Ss=\E[%p1%d q:Se=\E[6 q'

      set -g allow-passthrough on
      set -s extended-keys on
      set -as terminal-features 'xterm*:extkeys'
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
      set -g history-limit 50000

      set -g set-clipboard on

      set-option -g renumber-windows on
      set -g base-index 1
      setw -g pane-base-index 1

      # 窗口自动命名取的是 pane_current_command,而 nix 的 wrapProgram 会把真二进制
      # 改名成 .foo-wrapped、在 foo 位置放一个 exec 它的壳脚本 —— 于是状态栏上一排
      # .claude-wrapped / .nvim-wrapped。这里在默认格式的基础上剥掉前导 `.` 和结尾
      # `-wrapped`,没被包过的名字原样透出。
      #
      # 默认值是 `#{?pane_in_mode,[tmux],#{pane_current_command}}#{?pane_dead,[dead],}`,
      # 两个分支标记都留着,只把中间那个变量套了两层 #{s|re|repl|:...}。
      # 注意 s|| 的第三段必须是格式变量,塞字面量展开出来是空的。
      set -g automatic-rename-format '#{?pane_in_mode,[tmux],#{s|-wrapped$||:#{s|^\.||:#{pane_current_command}}}}#{?pane_dead,[dead],}'

      # 应用通过 OSC 0/2 设的标题会落在 pane_title,tmux 一直在收但默认不往外传
      # (set-titles 默认 off)。透传给外层终端:长而多变的东西放标题栏,dotbar 里
      # 保持干净的窗口名。Claude Code 的 pane_title 是 spinner + 当前任务摘要,
      # 正适合这里 —— 但正因为它一直在变、还很长,不能拿去当窗口名。
      #
      # 顺带一提 allow-rename(默认 off)是另一条路:让应用用 ESC k 直接改窗口名。
      # 不开 —— 那等于 pane 里流过的任何字节都能改窗口名,cat 个文件都行。
      set -g set-titles on
      set -g set-titles-string '#{pane_title}'

      # hostname 是静态的,这条不是为它设的 —— 是为了 @agent_state 那个标记跟手:
      # 默认 15s 意味着 agent 卡在权限提示上之后,最坏要等 15 秒状态栏才变。
      # 代价是 dotbar 的 ssh 窗口格式里那段 #() 会每秒跑一次(只影响 ssh 窗口);
      # 要是同时开一堆 ssh 窗口觉得吵,把这里调大即可。
      set -g status-interval 1

      bind r source-file ~/.config/tmux/tmux.conf \; display '~/.config/tmux/tmux.conf sourced'
      set -g prefix C-b
      bind C-b send-prefix

      # ---- 键位分工,照 hyprland 那套映射过来 ----
      #
      #   hyprland                              tmux
      #   $mod + ←→↑↓          resizeactive     prefix + ←→↑↓        resize-pane
      #   $mod + h/j/k/l       movefocus        prefix + h/j/k/l     select-pane
      #   $mod SHIFT + h/j/k/l movewindow       prefix + H/J/K/L     swap-pane
      #   $mod + 1..9          workspace        prefix + 1..9        select-window(默认)
      #
      # 大写本来就要按 Shift,所以 `prefix H` 天然对应 `$mod SHIFT + h` ——
      # 不加 Shift 移动焦点、加 Shift 搬东西,两边是同一套。
      #
      # swap-pane **不要加 -d**。不加时焦点跟着自己的 pane 走,加了会留在原位
      # 盯着换过来的那一个。独立 socket 实测:
      #   初始              %0*@x=0   %1@x=41
      #   -s '{right-of}'   %1@x=0    %0*@x=41    ← 焦点跟着 %0 到了右边
      #   加 -d             %1*@x=0   %0@x=41     ← 焦点留在左边,不是想要的
      #
      # swap-window 恰好相反,**必须补 select-window**:
      #   0:a 1:b*  --swap-window -t +->  0:a 1:c* 2:b   ← b 挪走了,人没跟过去
      #
      # `-t -` / `-t +` 是文档里的 target-window 记号(前一个/后一个编号)。
      # 到处流传的 `-t -1` 不是文档写法,解析结果不可预期。边界会环绕,实测正常。
      #
      # `<` / `>` 在 tmux 3.6 的默认是 display-menu(window 菜单 / pane 菜单),
      # 这里覆盖掉了。那两个菜单鼠标右键还能出来,不算真丢。
      bind -r h select-pane -L
      bind -r j select-pane -D
      bind -r k select-pane -U
      bind -r l select-pane -R

      bind -r H swap-pane -s '{left-of}'
      bind -r J swap-pane -s '{down-of}'
      bind -r K swap-pane -s '{up-of}'
      bind -r L swap-pane -s '{right-of}'

      # 小写 l 抢走了默认的 last-window,挪到 Tab —— 语义上也更像 alt-tab。
      # 别加 -r:重复模式下按 Tab 会在两个窗口之间反复横跳。
      bind Tab last-window

      bind -r < swap-window -t - \; select-window -t -
      bind -r > swap-window -t + \; select-window -t +

      # resize 从 HJKL 让位到方向键。方向键的默认绑定 select-pane 被顶掉了,
      # 但那个职责已经由上面的小写 hjkl 接手,没有净损失。
      bind -r Up    resize-pane -U 5
      bind -r Down  resize-pane -D 5
      bind -r Left  resize-pane -L 5
      bind -r Right resize-pane -R 5

      # 无参 swap-pane = 跟 `select-pane -m` 标记的那个交换,和上面不冲突,留着。
      bind | swap-pane

      setw -g mode-keys vi
      bind -T copy-mode-vi v send-keys -X begin-selection
      bind -T copy-mode-vi y send-keys -X copy-selection-and-cancel

      bind -T root C-g \
        set prefix None \;\
        set key-table off \;\
        set status-style 'fg=colour245,bg=colour238' \;\
        if -F '#{pane_in_mode}' 'send-keys -X cancel' \;\
        refresh-client -S \

      bind -T off C-g \
        set -u prefix \;\
        set -u key-table \;\
        set -u status-style \;\
        refresh-client -S
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
            datetime_timezone "Asia/Hong_Kong"
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
      strategy = ["history" "completion"];
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
      # cat = "bat --color always --plain";
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
    settings = {
      add_newline = false;
    };
  };

  xdg.configFile = {
    kvim.source = inputs.kvim.outPath;
    wezterm.source = inputs.wezterm-config.outPath;
    fastfetch = {
      source = ../../modules/fastfetch;
      recursive = true;
    };
  };

  # Claude Code 的状态栏脚本。只托管脚本,不托管 settings.json:
  # /model、/effort 会在运行时写回 settings.json,那个文件一旦变成 store 里的
  # 只读软链,这些斜杠命令就存不下来了。settings.json 里按这个路径引用:
  #   "statusLine": {
  #     "type": "command",
  #     "command": "bash /home/hank/.claude/statusline-command.sh",
  #     "refreshInterval": 1
  #   }
  # refreshInterval 是必须的:窗口 resize 不会触发状态栏重绘,而右对齐要靠 COLUMNS。
  home.file.".claude/statusline-command.sh" = {
    source = ../../modules/claude-code/statusline.sh;
    executable = true;
  };

  # Agent 状态写进 tmux 窗口列表。同样只托管脚本,hooks 要自己加进 settings.json:
  #   "hooks": {
  #     "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "$HOME/.claude/tmux-agent-status.sh working"}]}],
  #     "Notification":     [{"hooks": [{"type": "command", "command": "$HOME/.claude/tmux-agent-status.sh blocked"}]}],
  #     "Stop":             [{"hooks": [{"type": "command", "command": "$HOME/.claude/tmux-agent-status.sh done"}]}],
  #     "SessionEnd":       [{"hooks": [{"type": "command", "command": "$HOME/.claude/tmux-agent-status.sh clear"}]}]
  #   }
  # 用 $HOME 不写死路径:darwin 是 /Users/hank,NixOS 那边是 /home/hank,而
  # settings.json 不归 nix 管、不会按机器分叉。
  home.file.".claude/tmux-agent-status.sh" = {
    source = ../../modules/claude-code/tmux-agent-status.sh;
    executable = true;
  };

  home.file.".local/share/fonts/Recursive-Bold.ttf".source = ../../../fonts/Recursive-Bold.ttf;
  home.file.".local/share/fonts/Recursive-Italic.ttf".source = ../../../fonts/Recursive-Italic.ttf;
  home.file.".local/share/fonts/Recursive-Regular.ttf".source = ../../../fonts/Recursive-Regular.ttf;
  # home.file.wallpapers.source = ../../../wallpapers;

  # snacks.image 靠终端名判断能不能画图:它拿到终端名后剥掉 `xterm-` 前缀,再去
  # match kitty/ghostty/wezterm。ghostty 默认的 xterm-ghostty 剥完正好是 ghostty,
  # 但我们在 modules/ghostty 里把 term 设成了 xterm-256color(远端没有 ghostty 的
  # terminfo,不这么设 ssh 过去就一团糟),剥完变成 "256color",match 不上 —— 于是
  # supports_terminal() 恒为 false,本地和 ssh 都画不出图。
  #
  # 而且这条路径在我们这儿是绕不开的:tmux 开了 extended-keys 之后 nvim 的
  # TermResponse 不触发,snacks 只能改问 tmux 要 client_termname(也就是 TERM),
  # 拿不到真正的 XTVERSION 应答。见 snacks/image/terminal.lua 与 folke/snacks.nvim#2332。
  #
  # SNACKS_<NAME> 是 snacks 内置的检测覆盖。设在这里而不是 nixvim 模块里,是因为
  # 这是"我坐在 ghostty 前面"这个事实,只对 hank 成立,不该替别的用户断言;而且它
  # 会被每台 nix 管的机器写进 shell 环境,ssh 过去自然生效,不用折腾 SendEnv。
  home.sessionVariables = {
    SNACKS_GHOSTTY = "1";
  };

  home.packages = [
    pkgs.zsh-completions

    # snacks.image 的转换在 **nvim 所在的机器** 上跑,所以 ssh 过去看图要求远端也有
    # 这两个。它们本来只在 profiles/dev.nix 里,而 dev profile 只有 b650 引了
    # (userModules.hank.dev),别的机器 ssh 过去 magick 不在,图就是出不来。
    # 提到这里 = 每台有 hank 的机器都能看图,又不用把整套 dev 工具链背过去。
    #
    # dev.nix 里那份没删:它同时被 linwhite/dev.nix 引着。b650 上两边都声明,指向
    # 同一个 derivation,profile 里会去重,无害。
    # mermaid(mmdc)和 tectonic 仍然只在 dev profile —— 那两个是真的重。
    pkgs.imagemagick
    pkgs.ghostscript
  ];
}
