# 把 nixvim 用的 token 配色铺到终端和命令行工具上。
#
# 唯一的事实来源是下面的 `colors`(token 经典 appearance 的 dark 变体),
# 每个工具的配色都从它推出来,而不是各自抄一遍十六进制。上游 `contrib/`
# 下有成品配置文件,这里没有直接下发那些文件 —— 按仓库规矩全部翻成各模块
# 的原生 option。两个例外:bat 的 .tmTheme 是资源文件,carapace 在
# home-manager 里根本没有配色 option。
#
# 覆盖到的:ghostty、tmux、fzf、bat、delta、ripgrep、lazygit、starship、
# zsh、carapace。
#
# nvim 不在这里,它在 home/modules/nixvim/ 里自己 setup。
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.my.theme.token;
  c = cfg.colors;

  # 某个程序是不是既被 import 了、又开着。headless 的 home 里没有 ghostty
  # 这类模块,`or false` 让整条定义直接不生成。
  on = name: config.programs.${name}.enable or false;

  # 终端 ANSI 0-15。
  ansi = [
    c.bg1 # 0  black
    c.red # 1
    c.green # 2
    c.yellow # 3
    c.blue # 4
    c.purple # 5
    c.cyan # 6
    c.fg1 # 7  white
    c.fg3 # 8  bright black
    c.accent # 9  bright red,也是主强调色
    c.bright_green # 10
    c.accent2 # 11
    c.bright_blue # 12
    c.bright_purple # 13
    c.bright_cyan # 14
    c.fg0 # 15 bright white
  ];

  # rg 的 --colors 只吃 0xRR,0xGG,0xBB,不认 #rrggbb。
  rgb = hex: let
    p = n: "0x" + builtins.substring n 2 hex;
  in "${p 1},${p 3},${p 5}";

  # LS_COLORS 里的 24 位色要十进制 "R;G;B",nix 没有现成的 hex 解析。
  hexDigits = {
    "0" = 0;
    "1" = 1;
    "2" = 2;
    "3" = 3;
    "4" = 4;
    "5" = 5;
    "6" = 6;
    "7" = 7;
    "8" = 8;
    "9" = 9;
    a = 10;
    b = 11;
    c = 12;
    d = 13;
    e = 14;
    f = 15;
  };
  byte = hex: n:
    16 * hexDigits.${lib.toLower (builtins.substring n 1 hex)}
    + hexDigits.${lib.toLower (builtins.substring (n + 1) 1 hex)};
  # "38;2;R;G;B" —— SGR 的 24 位前景色。
  fg = hex: "38;2;${toString (byte hex 1)};${toString (byte hex 3)};${toString (byte hex 5)}";
in {
  options.my.theme.token = {
    enable = lib.mkEnableOption ''
      把 token 配色铺到终端(ghostty / tmux)和命令行工具
      (fzf / bat / delta / ripgrep / lazygit / starship / zsh / carapace)。
      只对已经 enable 的程序生效
    '';

    src = lib.mkOption {
      type = lib.types.package;
      readOnly = true;
      description = ''
        token 上游源码。nixvim 的 buildVimPlugin 和 bat 的 .tmTheme 都从这里
        取,免得同一个 hash 写两遍。
      '';
    };

    colors = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      readOnly = true;
      description = "token 经典 appearance 的 dark 调色板。";
    };
  };

  config = lib.mkMerge [
    {
      my.theme.token = {
        # 上游没有稳定分支,tag 和 hash 一起手动升。
        src = pkgs.fetchFromGitHub {
          owner = "ThorstenRhau";
          repo = "token";
          tag = "v2.5.0";
          hash = "sha256-eEXySoETgCvoi9wWfGAnG5/1Zn7DhVZkGeOmDdc8jUE=";
        };

        # 抄自 lua/token/palette.lua 的 dark 分支。改这里就够,下面全是推导。
        colors = {
          bg0 = "#191918"; # 浮窗
          bg1 = "#1d1d1c"; # 菜单 / 状态栏
          bg2 = "#212120";
          bg3 = "#262624"; # 编辑区正底色
          bg4 = "#2f2f2d"; # 光标行
          bg5 = "#383835";
          fg0 = "#e8e4dc";
          fg1 = "#d4cfc6";
          fg2 = "#938e87"; # 注释 / 次要文字
          fg3 = "#5a5955"; # 边框 / 最暗
          accent = "#d97757"; # 函数、标题、活动焦点
          accent2 = "#c4956a"; # 关键字、控制流
          blue = "#7b9ebd";
          green = "#7da47a";
          red = "#c67777";
          yellow = "#c4a855";
          purple = "#a68bbf";
          cyan = "#6ba8a8";
          orange = "#d4914a";
          olive = "#a8b56b";
          bright_green = "#98bf95";
          bright_blue = "#96b8d3";
          bright_purple = "#bea5d4";
          bright_cyan = "#88c0c0";
          sel = "#3a3a37"; # 选区
          match = "#4a4030"; # 搜索命中
          line_nr = "#585855";
          # diff 底色,给 delta 用
          diff_add_inline = "#2e5232";
          diff_del_inline = "#5a2529";
          diff_add_strong = "#3a6e3e";
          diff_del_strong = "#7a2e34";
          diff_text = "#444039";
        };
      };
    }

    #### 终端 ####

    (lib.mkIf (cfg.enable && on "ghostty") {
      programs.ghostty = {
        themes.token-dark = {
          background = c.bg3;
          foreground = c.fg0;
          cursor-color = c.fg0;
          cursor-text = c.bg3;
          selection-background = c.sel;
          selection-foreground = c.fg0;
          palette = lib.imap0 (i: v: "${toString i}=${v}") ansi;
        };
        settings.theme = "token-dark";
      };
    })

    # tmux 是顺序执行的,mkAfter 排在模块那份 tokyonight 之后就赢了,不用
    # mkForce。status-left/right 和 window-status-format 里嵌了颜色,光设
    # *-style 盖不住,所以整条重写。
    (lib.mkIf (cfg.enable && on "tmux") {
      programs.tmux.extraConfig = lib.mkAfter ''
        set -g status-style "bg=${c.bg0},fg=${c.fg1}"
        set -g status-left-style "bg=${c.bg0},fg=${c.accent},bold"
        set -g status-right-style "bg=${c.bg0},fg=${c.fg2}"

        setw -g window-status-style "bg=${c.bg0},fg=${c.fg2}"
        setw -g window-status-current-style "bg=${c.bg0},fg=${c.blue},bold"
        setw -g window-status-activity-style "bg=${c.bg0},fg=${c.yellow}"
        setw -g window-status-bell-style "bg=${c.bg0},fg=${c.red}"
        setw -g window-status-format " #[fg=${c.fg2}]#I:#W "
        setw -g window-status-current-format " #[fg=${c.blue},bold]#I:#W "

        set -g status-left "#[fg=${c.accent},bold] #S #[fg=${c.fg3}]|#[fg=${c.blue}] #(whoami)@#H "
        set -g status-right "#[fg=${c.fg2}] #{pane_current_path} #[fg=${c.fg3}]|#[fg=${c.accent2}] %Y-%m-%d %H:%M:%S "

        set -g pane-border-style "fg=${c.fg3}"
        set -g pane-active-border-style "fg=${c.blue}"
        set -g window-style "bg=${c.bg3}"
        set -g window-active-style "bg=${c.bg3}"

        set -g message-style "bg=${c.bg3},fg=${c.fg0}"
        set -g message-command-style "bg=${c.bg3},fg=${c.fg0}"
        setw -g mode-style "bg=${c.sel},fg=${c.fg0}"
        setw -g clock-mode-colour "${c.accent}"
        set -g display-panes-active-colour "${c.accent}"
        set -g display-panes-colour "${c.fg3}"
      '';
    })

    #### 命令行工具 ####

    (lib.mkIf (cfg.enable && on "fzf") {
      programs.fzf.colors = {
        fg = c.fg0;
        bg = c.bg3;
        hl = c.accent;
        "fg+" = c.fg0;
        "bg+" = c.sel;
        "hl+" = c.accent;
        border = c.fg3;
        header = c.blue;
        gutter = c.bg3;
        spinner = c.accent2;
        info = c.fg2;
        pointer = c.accent;
        marker = c.green;
        prompt = c.accent;
      };
    })

    # .tmTheme 是资源文件不是配置,直接指到上游源码里那一份。
    (lib.mkIf (cfg.enable && on "bat") {
      programs.bat = {
        themes.token-dark = {
          src = cfg.src;
          file = "contrib/bat/token-dark.tmTheme";
        };
        config.theme = "token-dark";
      };
    })

    (lib.mkIf (cfg.enable && on "ripgrep") {
      programs.ripgrep.arguments = [
        "--colors=match:none"
        "--colors=match:fg:${rgb c.accent}"
        "--colors=match:style:bold"
        "--colors=path:none"
        "--colors=path:fg:${rgb c.blue}"
        "--colors=path:style:nobold"
        "--colors=line:none"
        "--colors=line:fg:${rgb c.fg2}"
        "--colors=line:style:nobold"
        "--colors=column:none"
        "--colors=column:fg:${rgb c.fg3}"
        "--colors=column:style:nobold"
      ];
    })

    # delta 的语法高亮用的是 bat 的主题缓存,所以 syntax-theme 只在 bat 也
    # 开着(= token-dark.tmTheme 会被下发、激活时 `bat cache --build`)的时候
    # 才设,否则 delta 会因为找不到主题名报警告。
    (lib.mkIf (cfg.enable && on "delta") {
      programs.delta.options =
        {
          # 值里**不要**自己加引号。上游 contrib 的 .gitconfig 里那圈引号是
          # 为了让 `#` 不被 git 当成注释起头,而 home-manager 生成 ini 时已经
          # 把整个值加了一层双引号 —— 自己再写就变成字面量引号,delta 解析
          # 颜色时会失败。
          dark = true;
          blame-palette = "${c.bg1} ${c.bg2} ${c.bg3} ${c.bg4} ${c.bg5}";
          commit-decoration-style = "${c.fg3} bold box ul";
          file-style = c.fg0;
          file-decoration-style = c.fg3;
          hunk-header-style = "file line-number syntax";
          hunk-header-decoration-style = "${c.fg3} box ul";
          hunk-header-file-style = "bold";
          hunk-header-line-number-style = "bold ${c.fg2}";
          line-numbers-left-style = c.fg3;
          line-numbers-right-style = c.fg3;
          line-numbers-minus-style = "bold ${c.red}";
          line-numbers-plus-style = "bold ${c.green}";
          line-numbers-zero-style = c.fg2;
          minus-style = "syntax ${c.diff_del_inline}";
          minus-non-emph-style = "syntax ${c.diff_del_inline}";
          minus-emph-style = "bold ${c.fg0} ${c.diff_del_strong}";
          minus-empty-line-marker-style = "syntax ${c.diff_del_inline}";
          plus-style = "syntax ${c.diff_add_inline}";
          plus-non-emph-style = "syntax ${c.diff_add_inline}";
          plus-emph-style = "bold ${c.fg0} ${c.diff_add_strong}";
          plus-empty-line-marker-style = "syntax ${c.diff_add_inline}";
          map-styles = "bold purple => syntax '${c.diff_text}', bold cyan => syntax '${c.diff_text}'";
        }
        // lib.optionalAttrs (on "bat") {syntax-theme = "token-dark";};
    })

    (lib.mkIf (cfg.enable && on "lazygit") {
      programs.lazygit.settings.gui.theme = {
        activeBorderColor = [c.accent "bold"];
        inactiveBorderColor = [c.fg3];
        searchingActiveBorderColor = [c.yellow "bold"];
        optionsTextColor = [c.blue];
        selectedLineBgColor = [c.sel];
        inactiveViewSelectedLineBgColor = [c.bg4];
        cherryPickedCommitFgColor = [c.blue];
        cherryPickedCommitBgColor = [c.bg4];
        markedBaseCommitFgColor = [c.purple];
        markedBaseCommitBgColor = [c.bg4];
        unstagedChangesColor = [c.red];
        defaultFgColor = [c.fg0];
      };
    })

    # starship 的调色板会覆盖同名的标准色,所以只要定义 red/green/blue…,
    # 各内置模块的默认样式就自动换成 token 的那几档,不用逐个模块重写。
    (lib.mkIf (cfg.enable && on "starship") {
      programs.starship.settings = {
        palette = "token";
        palettes.token = {
          bg = c.bg3;
          fg = c.fg0;
          muted = c.fg2;
          subtle = c.fg3;
          accent = c.accent;
          accent2 = c.accent2;
          blue = c.blue;
          green = c.green;
          red = c.red;
          yellow = c.yellow;
          purple = c.purple;
          cyan = c.cyan;
          orange = c.orange;
        };
      };
    })

    (lib.mkIf (cfg.enable && on "zsh") {
      programs.zsh = {
        autosuggestion.highlight = "fg=${c.line_nr}";

        # 只有 main 和 brackets 两个 highlighter 开着,别的 key 写了也不会
        # 被读到。
        syntaxHighlighting.styles = {
          unknown-token = "fg=${c.red}";
          reserved-word = "fg=${c.accent2}";
          alias = "fg=${c.blue}";
          suffix-alias = "fg=${c.blue}";
          global-alias = "fg=${c.blue}";
          builtin = "fg=${c.blue}";
          function = "fg=${c.accent}";
          command = "fg=${c.blue}";
          precommand = "fg=${c.accent2}";
          commandseparator = "fg=${c.fg2}";
          hashed-command = "fg=${c.blue}";
          autodirectory = "fg=${c.fg1},underline";
          path = "fg=${c.fg1},underline";
          path_pathseparator = "fg=${c.fg2},underline";
          path_prefix = "fg=${c.fg1},underline";
          globbing = "fg=${c.purple}";
          history-expansion = "fg=${c.purple}";
          single-quoted-argument = "fg=${c.green}";
          double-quoted-argument = "fg=${c.green}";
          dollar-quoted-argument = "fg=${c.green}";
          single-quoted-argument-unclosed = "fg=${c.red},underline";
          double-quoted-argument-unclosed = "fg=${c.red},underline";
          dollar-quoted-argument-unclosed = "fg=${c.red},underline";
          back-quoted-argument = "fg=${c.fg2}";
          assign = "fg=${c.fg0}";
          redirection = "fg=${c.purple}";
          comment = "fg=${c.fg2},italic";
          single-hyphen-option = "fg=${c.fg1}";
          double-hyphen-option = "fg=${c.fg1}";
          named-fd = "fg=${c.accent2}";
          arithmetic-expansion = "fg=${c.blue}";
          bracket-level-1 = "fg=${c.green}";
          bracket-level-2 = "fg=${c.accent2}";
          bracket-level-3 = "fg=${c.cyan}";
          bracket-error = "fg=${c.red}";
        };

        # zstyle 和 zle_highlight 在 programs.zsh 的 option 表里没有对应项,
        # 只能走 initContent。
        initContent = lib.mkMerge [
          # **必须排在 init-extra.zsh 之前**(它是 mkOrder 1000)。那里面的
          # `zstyle ':completion:*' list-colors ${(s.:.)LS_COLORS}` 是在
          # zstyle 那一刻就把 LS_COLORS 的值展开进去的,晚一步改就只影响
          # ls、影响不到补全菜单。
          (lib.mkOrder 900 ''
            # 追加而不是替换:LS_COLORS 里后面的条目盖前面的同名条目,所以
            # 这一段只抢走文件类型(目录、链接、可执行…),原来那份按扩展名
            # 上色的长列表原封不动留着。不想要就删掉这一行。
            export LS_COLORS="''${LS_COLORS}:di=1;${fg c.blue}:ln=${fg c.purple}:or=${fg c.red}:mi=9;${fg c.red}:so=${fg c.green}:pi=${fg c.yellow}:ex=${fg c.accent}:bd=${fg c.cyan}:cd=${fg c.cyan}:su=1;${fg c.red}:sg=1;${fg c.yellow}:tw=1;${fg c.green}:ow=4;${fg c.blue}:st=1;${fg c.blue}"
          '')

          (lib.mkAfter ''
            zle_highlight=(''${zle_highlight:#region:*})
            zle_highlight=(''${zle_highlight:#paste:*} "region:fg=${c.fg0},bg=${c.sel}" "paste:fg=${c.fg0},bg=${c.sel}")

            zstyle ':fzf-tab:*' fzf-flags \
              '--color=fg:${c.fg0},bg:${c.bg3},hl:${c.accent}' \
              '--color=fg+:${c.fg0},bg+:${c.sel},hl+:${c.accent}' \
              '--color=border:${c.fg3},header:${c.blue},gutter:${c.bg3}' \
              '--color=spinner:${c.accent2},info:${c.fg2}' \
              '--color=pointer:${c.accent},marker:${c.green},prompt:${c.accent}'
          '')
        ];
      };
    })

    # home-manager 的 programs.carapace 只有 enable 和几个集成开关,没有配色
    # option,只能自己生成 styles.json。内容仍然是从上面的调色板推出来的。
    (lib.mkIf (cfg.enable && on "carapace") {
      xdg.configFile."carapace/styles.json".text = builtins.toJSON {
        carapace = {
          Description = c.fg2;
          Error = c.red;
          FlagArg = c.blue;
          FlagMultiArg = c.purple;
          FlagNoArg = c.fg1;
          FlagOptArg = c.cyan;
          Highlight1 = c.blue;
          Highlight2 = c.green;
          Highlight3 = c.accent2;
          Highlight4 = c.purple;
          Highlight5 = c.cyan;
          Highlight6 = c.yellow;
          Highlight7 = c.accent;
          Highlight8 = c.red;
          Highlight9 = c.fg1;
          Highlight10 = c.fg2;
          Highlight11 = c.olive;
          Highlight12 = c.orange;
          KeywordAmbiguous = c.yellow;
          KeywordNegative = c.red;
          KeywordPositive = c.green;
          KeywordUnknown = c.fg2;
          LogLevelCritical = c.red;
          LogLevelDebug = c.fg2;
          LogLevelError = c.red;
          LogLevelFatal = c.red;
          LogLevelInfo = c.blue;
          LogLevelTrace = c.fg2;
          LogLevelWarning = c.yellow;
          Usage = c.fg2;
          Value = c.fg1;
        };
      };
    })
  ];
}
