{
  config,
  lib,
  inputs,
  pkgs,
  pkgs-unstable,
  ...
}: let
  tmux-agent-sidebar = pkgs.callPackage ../../../pkgs/tmux-agent-sidebar {};
in {
  imports = [
    # 精简版 nixvim(nix 支持常开);dev.nix 会把 my.nixvim.dev.enable 打开
    ../../modules/nixvim
    # 只 import 不 enable:2026-08-28 整套试过一轮,终端那边不合用,退回
    # kanso + evergarden。模块留着(默认关),想再试就
    # `my.theme.token.enable = true`。import 在这里的另一个作用是让它继续
    # 参与求值,不会烂在仓库里没人发现。
    ../../modules/token-theme
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
        email = "hankchogan@gmail.com";
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
    escapeTime = 0;
    focusEvents = true;
    historyLimit = 50000;
    baseIndex = 1;
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
      # IP / UUID / docker 镜像 / 十六进制色值旁边浮出字母提示,按字母就抓走
      # —— 不进 copy-mode、不用移动光标。
      #
      # 占掉了默认的 `prefix Space`(next-layout)。真要切布局还有 `prefix M-1`
      # 到 `M-7` 直接选。
      #
      # **必须覆盖 @thumbs-command,默认的抓不到系统剪贴板。** 它默认是
      # `tmux set-buffer -- {}`,只填 tmux 内部的 paste buffer;而 set-buffer
      # 不带 -w 时不发 OSC 52,所以 ssh 过来的时候本机剪贴板里什么都没有。
      # (鼠标选和 prefix [ 之所以正常,是因为那两条走 copy-mode 通路,会遵守
      # 上面的 `set -g set-clipboard on` 发 OSC 52。)
      #
      # 加 -w 就是让它走同一条已经验证可用的通路:man 里写 "If -w is given,
      # the buffer is also sent to the clipboard for target-client using the
      # xterm(1) escape sequence"。
      #
      # 另一条路是 `set -g @thumbs-osc52 1`(让 thumbs 自己吐 OSC 52),没用它
      # —— 复用 tmux 已经跑通的机制比再引入一份实现可靠。
      {
        plugin = tmux-thumbs;
        extraConfig = ''
          set -g @thumbs-key space
          # 相同文本共用一个提示,省字母(默认 disabled)
          set -g @thumbs-unique enabled
          # 提示从靠近光标处开始编号,常用的落在单字母上(默认 disabled)
          set -g @thumbs-reverse enabled

          set -g @thumbs-command 'tmux set-buffer -w -- {} && tmux display-message "已复制 {}"'
          # 大写提示 = 复制并直接粘到当前 pane
          set -g @thumbs-upcase-command 'tmux set-buffer -w -- {} && tmux paste-buffer && tmux display-message "已粘贴 {}"'
        '';
      }

      # 跨 session/window 监控 Claude Code 的侧边栏。prefix e 开当前 window,
      # prefix E 开所有 window。包在 pkgs/tmux-agent-sidebar —— 上游只给 TPM
      # 装法,那条路会往插件目录里写下载来的二进制,在 store 里行不通。
      #
      # hook 那半边不归 nix 管,见下面 home.file 里 .claude/plugin-sources 那条。
      {
        plugin = tmux-agent-sidebar;
        # agent-sidebar.conf 里这些选项全是 `if -F '#{==:#{@x},}'` 的
        # 「没设才给默认值」,而 home-manager 把插件自己的 extraConfig 排在它的
        # run-shell **前面** —— 所以这里设的值会被 conf 认账。和 dotbar 同一条
        # 规矩,写到 programs.tmux.extraConfig 里就晚了。
        extraConfig = ''
          set -g @sidebar_position right

          # 上游默认 on:每开一个新 window 都自动塞一个侧边栏 pane 进去。
          # 关掉,只在按 prefix e 的时候出现。
          set -g @sidebar_auto_create off
        '';
      }
    ];
    extraConfig = ''
      set-option -ga terminal-overrides ",*256col*:Tc"
      set -ga terminal-overrides ',*:Ss=\E[%p1%d q:Se=\E[6 q'

      set -g allow-passthrough on
      set -s extended-keys on
      # tmux 默认发 xterm 的 modifyOtherKeys(^[[27;6;65~),pi 两种都解析但
      # csi-u(^[[65;6u)才是它的一等公民,带修饰的可打印键走的是打磨较少的分支。
      set -s extended-keys-format csi-u
      set -as terminal-features 'xterm*:extkeys'
      set -ga update-environment TERM
      set -ga update-environment TERM_PROGRAM

      setw -g xterm-keys on
      # escape-time / focus-events / history-limit / base-index 挪到 Nix 侧原生选项了;
      # status-utf8 / utf8 两行删除的原因见 docs/decisions.md#tmux-dead-settings。
      set -sg repeat-time 300
      set -sg exit-empty on

      set -g visual-activity off
      setw -g monitor-activity off
      setw -g monitor-bell off

      set -g set-clipboard on
      # tmux 只在外层终端的 terminfo 里有 `Ms` 时才肯发 OSC 52(man:
      # "if there is an Ms entry in the terminfo description")。而 ghostty 和
      # kitty 的条目(xterm-ghostty / xterm-kitty)在不少机器上压根没安装 ——
      # ssh 过去 TERM 落不到带 Ms 的条目上,set-clipboard 和 `set-buffer -w`
      # 就一起静默失效,剪贴板里什么都没有还不报错。
      #
      # 直接对所有终端声明这个能力。ghostty / kitty / wezterm / iTerm 都支持
      # OSC 52;万一碰上不支持的,它只会把这段转义序列忽略掉,没有副作用。
      set -ga terminal-overrides ',*:Ms=\E]52;%p1%s;%p2%s\007'

      set-option -g renumber-windows on

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
      # swap-pane 不加 -d(焦点跟着自己的 pane 走),swap-window 必须补
      # select-window(否则窗口挪了人没跟过去);两处的实测过程和 `-t -` 与
      # `-t -1` 的辨析见 docs/incidents.md#tmux-swap-focus。
      #
      # `<` / `>` 覆盖 tmux 3.6 默认的 display-menu,那两个菜单鼠标右键还能出来,不算真丢。
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
      lvim = "NVIM_APPNAME=lazyvim nvim";
      dvim = "NVIM_APPNAME=dvim nvim";

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
      gp = "git push";
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

      # def p 删了 —— 和 zsh 那边的 p 别名一样,默认参数是 "update",
      # 用着用着提交信息就全变成 update 了。
    '';
    extraEnv = ''
      # $env.PATH = ($env.PATH | split row (char esep) | prepend '~/.cargo/bin')
    '';
  };

  programs.zsh = {
    enableCompletion = true;
    autocd = true;
    defaultKeymap = "viins";

    # 补全缓存提速。系统那份 compinit 和 home-manager 这份会抢同一个
    # ~/.zcompdump 并互相判废,每开一个 shell 白花 ~1170ms;`-d` 给这份一个
    # 自己的 dump,`-C` 再跳过扫描。详见 docs/incidents.md#zsh-double-compinit。
    #
    # 去重 fpath 时**只拿解析后的真实路径当 key,保留原来的写法** —— 换成
    # /nix/store/... 的真实路径会让 compaudit 把整个 fpath 判成 insecure,
    # 在没有 tty 的嵌套 shell 里直接 "initialization aborted"。
    #
    # -C 的代价是装了新工具 dump 不会自己更新,所以下面配了 activation 在每次
    # home-manager 切换后删掉它。
    # (这段是在 .zshrc 顶层展开的,不是函数体,所以不能用 local,只能自己收尾。)
    completionInit = ''
      typeset -A _hm_seen
      typeset -a _hm_fp
      for _hm_d in $fpath; do
        # 只丢掉**版本对不上**的那份 zsh 自带函数目录,不能无脑丢 /usr/share/zsh/*。
        # 这台机器的登录 shell 是 /bin/zsh(Apple 的 5.9),它跑起来时 home-manager
        # 按 $ZSH_VERSION 拼出的 ~/.nix-profile/share/zsh/5.9/functions 是空的,
        # compdump / compinstall 这些只存在于 /usr/share/zsh/5.9/functions ——
        # 一并删掉的话 compinit 直接报 "compdump: function definition file not found"。
        [[ $_hm_d == /usr/share/zsh/*/functions && $_hm_d != /usr/share/zsh/$ZSH_VERSION/functions ]] && continue
        [[ -n ''${_hm_seen[''${_hm_d:A}]} ]] && continue
        _hm_seen[''${_hm_d:A}]=1
        _hm_fp+=($_hm_d)
      done
      fpath=($_hm_fp)

      autoload -Uz compinit
      # dump 的目录 home-manager 不会替我们建(它只给 HISTFILE 建),新机器上
      # 少了这行 compinit 就写不出 dump,于是每次启动都重扫一遍 —— 正是要修的病。
      _hm_zdump="''${XDG_CACHE_HOME:-$HOME/.cache}/zsh/zcompdump-$ZSH_VERSION"
      [[ -d ''${_hm_zdump:h} ]] || mkdir -p ''${_hm_zdump:h}
      compinit -C -d "$_hm_zdump"
      unset _hm_seen _hm_fp _hm_d _hm_zdump
    '';

    autosuggestion = {
      enable = true;
      strategy = ["history" "completion"];
    };

    historySubstringSearch.enable = true;

    # 这里**不要**写 main:home-manager 生成的是 ZSH_HIGHLIGHT_HIGHLIGHTERS=(main …),
    # 自己再列一遍就成了 (main main brackets),main 每次按键跑两遍。
    #
    # pattern / regexp / line 都删了:它们要先自己定义 ZSH_HIGHLIGHT_PATTERNS、
    # ZSH_HIGHLIGHT_REGEXP 或 ZSH_HIGHLIGHT_STYLES[line] 才有输出,实测三个的样式
    # 全是 <未定义>,纯粹是每次按键多跑一遍。root 只在 uid 为 0 的 shell 里才变色,
    # 平时用 sudo 也触发不到。
    syntaxHighlighting = {
      enable = true;
      highlighters = ["brackets"];
    };

    history = {
      size = 10000;
      save = 10000;
      # 历史是攒出来的,不该放在一个"随时可以删干净"的目录里。
      path = "$HOME/.local/state/zsh/history";
      share = true;
      extended = true;
      ignoreSpace = true;
      ignoreAllDups = true;
      saveNoDups = true;
      # expireDuplicatesFirst 没有配:它是在历史写满时优先淘汰重复项,而
      # ignoreAllDups 压根不让重复项进来,两个一起开时后者永远没东西可淘汰。
    };

    # 删掉的四个都是白写的:NOTIFY 和 HASH_LIST_ALL 本来就是 zsh 默认开,
    # CORRECT 本来就是默认关(所以 NO_CORRECT 是空操作),MAILWARN 则是让 zsh
    # 惦记 $MAIL 有没有新邮件 —— 开发机上纯属浪费一次 stat。
    setOptions = [
      "AUTO_MENU"
      "AUTO_PARAM_SLASH"
      "COMPLETE_IN_WORD"
      "NO_MENU_COMPLETE"
      "ALWAYS_TO_END"
      "NOHUP"
      "INTERACTIVE_COMMENTS"
      "NOBEEP"
      "HIST_NO_FUNCTIONS"
      "HIST_REDUCE_BLANKS"
      "NO_FLOW_CONTROL"
      "NO_NOMATCH"
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
      # zsh-history-search-multi-word 去掉了:它唯一的入口是 ^R,而 programs.fzf 的
      # zsh 集成在插件之后加载、把 ^R 抢成了 fzf-history-widget。插件一直在被加载、
      # 函数也定义着,但没有任何按键能到达它。
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
      # p 去掉了:git add . && git commit -am 'update' && git push,提交信息永远是
      # "update"。真要一把梭也该自己写一句人话,不该有个一键别名让人手滑。
      # getidf / brew86 也去掉了:~/esp 和 /usr/local/homebrew 都不存在了。
      lg = "lazygit";
      lvim = "NVIM_APPNAME=lazyvim nvim";
      dvim = "NVIM_APPNAME=dvim nvim";

      # general
      # settings / cleanram / trim_all 只在 Linux 机器上有意义,留着 —— 这台 mac
      # 的 history 里没出现过不代表没用过(GNOME 装在 b650/x470/m16/tank 上)。
      settings = "gnome-control-center";
      cleanram = "sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'";
      trim_all = "sudo fstrim -va";
      c = "clear";
      q = "exit";
      ".." = "cd ..";
      mkdir = "mkdir -p";
      #
      # 这一轮又删掉的(抄来的、目标不存在的、或者不如直接敲的):
      #   run=pnpm run   pnpm 只在 kenneth 的配置里,hank 一台都没装
      #   ra=joshuto     joshuto 全仓库没有任何 host 装
      #   nvid=neovide   同上
      #   mkgrub         NixOS 的 grub 配置是 nixos-rebuild 生成的,手跑这个只会帮倒忙
      #   mtar/utar/uz   tar -zcvf / -zxvf / unzip 的包装,省不了几个字还得先想别名叫啥
      #   psg            ps aux | grep 的包装,procs 或直接管道都比它清楚
      # 更早一轮删的:fm=ranger(已换成 yazi 的 y)、整块 pacman/paru(没有 Arch 机器)。

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
      # rm 不带 -r:递归删除应该是每次显式打出来的那个字母,不该是默认值。
      rm = "rm -v";

      # git —— 这份保持和上面 nushell 那份一致,再加几个日志 / rebase / stash 的常用项。
      # 原来这里是从 oh-my-zsh 整包抄来的 176 个 g* 别名,而 history 里真正出现过的只有
      # 8 个(ga gb gc gcl gco gl gp gst)。删掉的那些在 git log 里找得回来。
      #
      # 需要 $(git_main_branch) / $(git_develop_branch) 的那些一个没留:那几个 helper
      # 每次展开都要 fork 一串 git show-ref,而"主干叫什么"这件事在这个仓库里是常数。
      g = "git";
      ga = "git add";
      gaa = "git add --all";
      gap = "git add --patch";

      gb = "git branch";
      gba = "git branch -a";
      gbd = "git branch -d";
      gbD = "git branch -D";

      gc = "git commit -v";
      "gc!" = "git commit -v --amend";
      gca = "git commit -v -a";
      "gca!" = "git commit -v -a --amend";
      gcam = "git commit -a -m";
      "gcn!" = "git commit -v --no-edit --amend";

      gco = "git checkout";
      gcb = "git checkout -b";
      gsw = "git switch";
      gswc = "git switch -c";

      gcl = "git clone";
      gd = "git diff";
      gdca = "git diff --cached";
      gf = "git fetch";
      gfa = "git fetch --all --prune";
      gl = "git pull";
      gpr = "git pull --rebase";
      gp = "git push";
      gpf = "git push --force-with-lease";
      gpsup = ''git push --set-upstream origin "$(git branch --show-current)"'';

      glo = "git log --oneline --decorate";
      glog = "git log --oneline --decorate --graph";
      gloga = "git log --oneline --decorate --graph --all";

      gm = "git merge";
      grb = "git rebase";
      grba = "git rebase --abort";
      grbc = "git rebase --continue";
      grbi = "git rebase -i";

      gr = "git remote";
      grv = "git remote -v";
      grh = "git reset";
      grhh = "git reset --hard";
      grs = "git restore";
      grst = "git restore --staged";

      gsb = "git status -sb";
      gss = "git status -s";
      gst = "git status";
      gsh = "git show";

      gsta = "git stash push";
      gstp = "git stash pop";
      gstl = "git stash list";

      grt = ''cd "$(git rev-parse --show-toplevel || echo .)"'';
    };

    # envExtra 搬到下面的 home.sessionPath / home.sessionVariables 去了。
    # 两个原因:一是这些 export 写进 .zshenv 而 .zshenv 每层嵌套 shell 都会重跑,
    # PATH 会一层层往上叠(实测嵌套一次就多出一个 /opt/homebrew/opt/rustup/bin);
    # home-manager 生成的 hm-session-vars.sh 自带 __HM_SESS_VARS_SOURCED 卫兵,
    # 只跑一次。二是你同时在用 nushell,而 .zshenv 里的东西 nushell 一个也拿不到。

    # init-extra.zsh 里那些函数的实现都在这儿。siteFunctions 把每个 value 写成
    # ~/.nix-profile/share/zsh/site-functions/<key> 并 `autoload -Uz <key>` ——
    # 也就是**按需加载**,而不是每开一个 shell 都把函数体重新执行一遍定义。
    #
    # key 是函数名、value 是函数体(不要自己写 `name() { }` 外壳)。
    siteFunctions = {
      # sops 路径补全的替代实现,见 init-extra.zsh 里 compdef 那段的注释。
      # 名字不能叫 _sops —— sops 包自己就往这个目录写同名文件,会撞车。
      _sops_files = ''
        local -a opts
        local cur=''${words[-1]}
        if [[ $cur == -* ]]; then
          opts=("''${(@f)$(_CLI_ZSH_AUTOCOMPLETE_HACK=1 ''${words[@]:0:#words[@]-1} ''${cur} --generate-bash-completion 2>/dev/null)}")
          [[ -n ''${opts[1]} ]] && _describe -t options 'option' opts
          return
        fi
        opts=("''${(@f)$(_CLI_ZSH_AUTOCOMPLETE_HACK=1 ''${words[@]:0:#words[@]-1} --generate-bash-completion 2>/dev/null)}")
        [[ -n ''${opts[1]} ]] && _describe -t commands 'command' opts
        _files
      '';

      # cd 之后自动列目录(chpwd hook)
      _auto_eza_ls = ''
        [[ -o interactive ]] && eza --color=auto --icons
      '';

      # vi 模式下 \e/ 直接进反向历史搜索
      _vi_search_fix = ''
        zle vi-cmd-mode
        zle .vi-history-search-backward
      '';

      # 双击 Esc 给当前行加/去 sudo(oh-my-zsh 的 sudo 插件)
      _sudo_replace_buffer = ''
        local old=$1 new=$2 space=''${2:+ }
        if [[ $CURSOR -le ''${#old} ]]; then
          BUFFER="''${new}''${space}''${BUFFER#$old }"
          CURSOR=''${#new}
        else
          LBUFFER="''${new}''${space}''${LBUFFER#$old }"
        fi
      '';
      _sudo_command_line = ''
        [[ -z $BUFFER ]] && LBUFFER="$(fc -ln -1)"
        local WHITESPACE=""
        if [[ ''${LBUFFER:0:1} = " " ]]; then
          WHITESPACE=" "
          LBUFFER="''${LBUFFER:1}"
        fi
        {
          local EDITOR=''${SUDO_EDITOR:-''${VISUAL:-$EDITOR}}
          if [[ -z "$EDITOR" ]]; then
            case "$BUFFER" in
              sudo\ -e\ *) _sudo_replace_buffer "sudo -e" "" ;;
              sudo\ *) _sudo_replace_buffer "sudo" "" ;;
              *) LBUFFER="sudo $LBUFFER" ;;
            esac
            return
          fi
          local cmd="''${''${(Az)BUFFER}[1]}"
          local realcmd="''${''${(Az)aliases[$cmd]}[1]:-$cmd}"
          local editorcmd="''${''${(Az)EDITOR}[1]}"
          if [[ "$realcmd" = (\$EDITOR|$editorcmd|''${editorcmd:c}) \
            || "''${realcmd:c}" = ($editorcmd|''${editorcmd:c}) ]] \
            || builtin which -a "$realcmd" | command grep -Fx -q "$editorcmd"; then
            _sudo_replace_buffer "$cmd" "sudo -e"
            return
          fi
          case "$BUFFER" in
            $editorcmd\ *) _sudo_replace_buffer "$editorcmd" "sudo -e" ;;
            \$EDITOR\ *) _sudo_replace_buffer '$EDITOR' "sudo -e" ;;
            sudo\ -e\ *) _sudo_replace_buffer "sudo -e" "$EDITOR" ;;
            sudo\ *) _sudo_replace_buffer "sudo" "" ;;
            *) LBUFFER="sudo $LBUFFER" ;;
          esac
        } always {
          LBUFFER="''${WHITESPACE}''${LBUFFER}"
          zle redisplay
        }
      '';

      # vi 模式光标形状:vicmd 块状 / viins 竖线
      _cursor_shape_keymap_select = ''
        if [[ ''${KEYMAP} == vicmd ]]; then
          echo -ne '\e[1 q'
        else
          echo -ne '\e[5 q'
        fi
      '';
      _cursor_shape_line_init = ''
        echo -ne '\e[5 q'
      '';

      proxy = ''
        local proxy_address="http://127.0.0.1:7890"
        export http_proxy="''${proxy_address}"
        export https_proxy="''${proxy_address}"
        export all_proxy="''${proxy_address}"
        export HTTP_PROXY="''${proxy_address}"
        export HTTPS_PROXY="''${proxy_address}"
        export ALL_PROXY="''${proxy_address}"
        echo "Proxy enabled (http/https/all -> ''${proxy_address})"
        env | grep -i "_proxy"
      '';
      unproxy = ''
        unset http_proxy https_proxy all_proxy
        unset HTTP_PROXY HTTPS_PROXY ALL_PROXY
        echo "Proxy disabled"
      '';
    };

    initContent = lib.mkMerge [
      # 必须排在 zsh-autosuggestions 被 source 之前,所以用 mkBefore 而不是
      # localVariables(那个是 mkOrder 540,落在插件后面就不生效了)。
      (lib.mkBefore ''
        ZSH_AUTOSUGGEST_USE_ASYNC="true"
      '')
      # zsh/zle 在交互 shell 里本来就是自动加载的(实测去掉这行它照样在);
      # zsh/zpty 由 zsh-autosuggestions 在真的要用 completion 策略时自己
      # `zmodload zsh/zpty 2>/dev/null || return`,轮不到我们提前加载。
      # complist 留着 —— 它不会自动加载,而 list-colors 要靠它给补全菜单上色。
      (lib.mkOrder 550 ''
        zmodload zsh/complist
      '')
      ''
        ${builtins.readFile ./init-extra.zsh}
      ''
      # macOS 那段原来是运行时 `if [ "$(uname)" = "Darwin" ]` 加一层
      # `if [ "$(uname -m)" = "x86_64" ]`,每开一个 shell fork 两次 uname 去问
      # 一件 nix 在求值期就知道的事。放在这里的结果是:Linux 上生成的 .zshrc 里
      # 根本不会出现这几行,mac 上则是常量,没有分支。
      (lib.optionalString pkgs.stdenv.isDarwin (let
        brewPrefix =
          if pkgs.stdenv.isAarch64
          then "/opt/homebrew"
          else "/usr/local";
      in ''
        source ~/.orbstack/shell/init.zsh 2>/dev/null || :
        alias matlabcli="/Applications/MATLAB_R2025a.app/bin/matlab -nodesktop -nosplash"
        export HOMEBREW_BOTTLE_DOMAIN=https://mirror.sjtu.edu.cn/homebrew-bottles

        # 这里原来是 eval "$(brew shellenv)" —— 每次开 shell fork 一个 bash 脚本,
        # 它自己再 fork 一次 /usr/libexec/path_helper,实测 ~55ms,而输出是常量。
        # 顺带甩掉 path_helper:它会按 /etc/paths 重排 PATH,把 /usr/bin 顶到 nix 前面。
        #
        # path/fpath 用数组前插,不是 export PATH="...:$PATH" —— 后者在嵌套 shell
        # 里会一层层叠上去(rustup 那条以前就是这么重复的)。
        export HOMEBREW_PREFIX="${brewPrefix}"
        export HOMEBREW_CELLAR="${brewPrefix}/Cellar"
        export HOMEBREW_REPOSITORY="${brewPrefix}"
        export INFOPATH="${brewPrefix}/share/info:''${INFOPATH:-}"
        path=("${brewPrefix}/bin" "${brewPrefix}/sbin" $path)
        fpath=("${brewPrefix}/share/zsh/site-functions" $fpath)
      ''
      + lib.optionalString pkgs.stdenv.isAarch64 ''
        path=("/opt/homebrew/opt/rustup/bin" $path)
      ''))
    ];
  };

  # git diff / show / log -p / blame 走 delta,取代原来的 diff.tool = nvimdiff。
  #
  # 没配 syntax-theme,用 delta 自带的默认。token 那套配色试过一轮不合用,
  # 见 my.theme.token(默认关着)。
  #
  # jujutsu 那边**没**开:delta 的 jj 集成会写 ui.diff-formatter = ":git",
  # 和下面 programs.jujutsu 里那句 "git" 撞;而且 ui.paginate = "never" 意味
  # 着 pager 根本不会启动,接上去也不生效。要用得先把那两项一起改。
  programs.delta = {
    enable = true;
    enableGitIntegration = true;
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
  #     "command": "bash /home/hank/.claude/statusline-command.sh"
  #   }
  # 全部内容都是左对齐、按调用顺序依次追加的,不读终端宽度,所以不需要
  # refreshInterval 之类的定时重绘 —— 每次渲染跑一遍就够了。
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

  # 侧边栏的另一半:Claude Code 要靠 hook 才拿得到 prompt / tool call /
  # subagent 树,而 hook 是以「plugin marketplace」的形式装的,它的 source 是一个
  # **目录的绝对路径**(记在 ~/.claude/plugins/known_marketplaces.json 里)。
  # 直接填 store 路径的话,每次升级路径一变就得重新 add;所以在固定位置放一个
  # 软链,marketplace 指着它,升级自动跟上。
  #
  # 装的动作本身是一次性的、不归 nix 管(和上面 statusline / tmux-agent-status
  # 一样,settings.json 不在 nix 手里):
  #   /plugin marketplace add ~/.claude/plugin-sources/tmux-agent-sidebar
  #   /plugin install tmux-agent-sidebar@hiroppy
  home.file.".claude/plugin-sources/tmux-agent-sidebar".source =
    "${tmux-agent-sidebar}/share/tmux-plugins/tmux-agent-sidebar";

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

    # 原来在 programs.zsh.envExtra 里,只有 zsh 看得见。
    KUBECONFIG = "${config.home.homeDirectory}/.config/k3s.yaml";
    TERMINAL = "ghostty";

    XDG_CONFIG_HOME = "${config.home.homeDirectory}/.config";
    XDG_CACHE_HOME = "${config.home.homeDirectory}/.cache";
    XDG_DATA_HOME = "${config.home.homeDirectory}/.local/share";
    XDG_STATE_HOME = "${config.home.homeDirectory}/.local/state";

    LESS = "--RAW-CONTROL-CHARS";
    MANPAGER = "less -s -M +Gg";

    # LESS_TERMCAP_* 没搬过来:那组的值必须是真的 ESC 字节,而这里生成的是
    # POSIX sh 的 export NAME="value",写不出 $'\e'。它们留在 init-extra.zsh。
  };

  # 这几个目录不是每台机器都有(.moon / .ghcup / .cargo 在这台 mac 上就没有),
  # 不存在的 PATH 项只是每次查找多一次 stat,留着比按 host 分叉省事。
  home.sessionPath = [
    "${config.home.homeDirectory}/.moon/bin"
    "${config.home.homeDirectory}/.ghcup/bin"
    "${config.home.homeDirectory}/.local/bin"
    "${config.home.homeDirectory}/.cargo/bin"
  ];

  # compinit -C 不再自己去发现新装的补全,所以每次 home-manager 切换后把 dump 删掉:
  # 之后第一个新开的 shell 会花 ~500ms 重建一次,后面又回到 ~280ms。
  home.activation.dropZcompdump = lib.hm.dag.entryAfter ["writeBoundary"] ''
    rm -f "${config.home.homeDirectory}/.cache/zsh/zcompdump-"*
  '';

  home.packages = [
    pkgs.zsh-completions

    # 二进制单独进 PATH,不只是躺在插件目录里:Claude Code 那份 hook.sh 是从
    # 它自己的 plugin cache 里跑的,查找顺序的最后一档才是 PATH —— 没有这条,
    # 它会退回 cache 里那个 TPM 时代下载来的副本。
    tmux-agent-sidebar

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
  ]
  # 下面这些原本在各自 host 的 environment.systemPackages 里。都是"我"用的
  # 单机工具,不是机器跑起来需要的,所以按 host 挂在这儿。
  #
  # iproute2mac 不在这儿:profiles/dev.nix 的 darwin 分支早就有了,
  # m1elite 的 system 那份纯属重复。
  ++ lib.optionals (config.my.host.name == "aarch64-wsl") [pkgs.distrobox]
  ++ lib.optionals (config.my.host.name == "r5sjp") [pkgs.wakeonlan]
  # tank 的图形界面是 host 级开的 hyprland,而 tank 的 hank 没引 gui.linux
  # (那行是注释掉的),所以 modules/gui 到不了这台 —— 它的桌面包只能挂这儿。
  ++ lib.optionals (config.my.host.name == "tank") [
    pkgs.waybar
    pkgs.nwg-dock-hyprland
    pkgs.brightnessctl
    pkgs.radeontop
    pkgs.clapper
    # waybar 的脚本要用。原注释写着 "make waybar happy",waybar 搬到哪它就跟到哪。
    (pkgs.python3.withPackages (ps: with ps; [pandas requests]))
  ]
  ++ lib.optionals (config.my.host.name == "m1elite") [
    # 用来推别的机器,不是这台 Mac 自己要的。
    pkgs.nixos-rebuild
    pkgs.nixos-rebuild-ng
  ];
}
