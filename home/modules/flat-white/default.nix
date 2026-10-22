# 仅由 linwhite 引入；所有颜色都来自已有的 flat-white 色卡。
{
  config,
  lib,
  pkgs,
  ...
}: let
  palette = import ../palettes/flat-white.nix;
  c = palette.colors;
  on = name: config.programs.${name}.enable or false;
  interactive = on "yazi";
  dev = config.my.nixvim.dev.enable;
  tmTheme = import ./tmtheme.nix {inherit pkgs;};
  named = {
    black = c.color0;
    red = c.color1;
    green = c.color2;
    yellow = c.color3;
    blue = c.color4;
    purple = c.color5;
    cyan = c.color6;
    white = c.color7;
    "bright-black" = c.color8;
    "bright-red" = c.color9;
    "bright-green" = c.color10;
    "bright-yellow" = c.color11;
    "bright-blue" = c.color12;
    "bright-purple" = c.color13;
    "bright-cyan" = c.color14;
    "bright-white" = c.color15;
  };
in {
  imports = [./shell.nix ./yazi.nix ./dev-tools.nix];

  programs.ghostty = lib.mkIf (on "ghostty") {
    settings.theme = "flat-white";
    themes.flat-white = {
      inherit (c) background foreground;
      cursor-color = c.cursor;
      cursor-text = c.cursor_text;
      selection-background = c.selection_bg;
      selection-foreground = c.selection_fg;
      palette = lib.imap0 (i: color: "${toString i}=${color}") palette.ansi;
    };
  };
  programs.wezterm = lib.mkIf (on "wezterm") {
    settings.color_scheme = "flat-white";
    colorSchemes.flat-white = {
      inherit (c) background foreground selection_bg selection_fg;
      cursor_bg = c.cursor;
      cursor_fg = c.cursor_text;
      cursor_border = c.cursor;
      ansi = lib.take 8 palette.ansi;
      brights = lib.drop 8 palette.ansi;
    };
  };
  programs.starship.settings = {
    palette = "flat-white";
    palettes.flat-white =
      named
      // {
        bg = c.background;
        fg = c.foreground;
        muted = c.color8;
      };
  };
  programs.fzf.colors = lib.mkIf (on "fzf") {
    bg = c.background;
    fg = c.foreground;
    hl = c.color3;
    "bg+" = c.selection_bg;
    "fg+" = c.selection_fg;
    "hl+" = c.color11;
    border = c.color8;
    header = c.color4;
    gutter = c.background;
    info = c.color8;
    pointer = c.color3;
    marker = c.color2;
    prompt = c.color4;
    spinner = c.color5;
  };
  programs.bat = lib.mkIf (interactive || dev) {
    enable = true;
    config.theme = "flat-white";
    themes.flat-white.src = tmTheme;
  };
  programs.btop = lib.mkIf interactive {
    enable = true;
    settings.color_theme = "flat-white";
    themes.flat-white = lib.concatStringsSep "\n" (lib.mapAttrsToList (name: color: ''theme[${name}]="${color}"'') {
      main_bg = c.background;
      main_fg = c.foreground;
      title = c.foreground;
      hi_fg = c.color4;
      selected_bg = c.selection_bg;
      selected_fg = c.selection_fg;
      inactive_fg = c.color8;
      graph_text = c.foreground;
      meter_bg = c.selection_bg;
      proc_misc = c.color6;
      cpu_box = c.color4;
      mem_box = c.color2;
      net_box = c.color5;
      proc_box = c.color6;
      div_line = c.color8;
      temp_start = c.color2;
      temp_mid = c.color3;
      temp_end = c.color1;
      cpu_start = c.color4;
      cpu_mid = c.color6;
      cpu_end = c.color2;
      free_start = c.color2;
      free_mid = c.color10;
      free_end = c.color10;
      cached_start = c.color5;
      cached_mid = c.color13;
      cached_end = c.color13;
      available_start = c.color6;
      available_mid = c.color14;
      available_end = c.color14;
      used_start = c.color3;
      used_mid = c.color11;
      used_end = c.color1;
      download_start = c.color4;
      download_mid = c.color12;
      download_end = c.color14;
      upload_start = c.color5;
      upload_mid = c.color13;
      upload_end = c.color9;
      process_start = c.color2;
      process_mid = c.color6;
      process_end = c.color4;
    });
  };
  programs.delta = lib.mkIf dev {
    enable = true;
    enableGitIntegration = true;
    options = {
      dark = true;
      syntax-theme = "flat-white";
      minus-style = "syntax ${c.color0}";
      plus-style = "syntax ${c.color0}";
      minus-emph-style = "${c.color9} ${c.selection_bg}";
      plus-emph-style = "${c.color10} ${c.selection_bg}";
      line-numbers-minus-style = c.color1;
      line-numbers-plus-style = c.color2;
      line-numbers-zero-style = c.color8;
      file-style = "${c.color4} bold";
      file-decoration-style = c.color4;
      hunk-header-style = "file line-number syntax";
      hunk-header-decoration-style = c.color8;
    };
  };
  programs.lazygit = lib.mkIf dev {
    enable = true;
    enableZshIntegration = false;
    settings.gui.theme = {
      activeBorderColor = [c.color4 "bold"];
      inactiveBorderColor = [c.color8];
      searchingActiveBorderColor = [c.color3 "bold"];
      optionsTextColor = [c.color6];
      selectedLineBgColor = [c.selection_bg];
      cherryPickedCommitFgColor = [c.color2];
      cherryPickedCommitBgColor = [c.color0];
      markedBaseCommitFgColor = [c.color5];
      markedBaseCommitBgColor = [c.color0];
      unstagedChangesColor = [c.color1];
      defaultFgColor = [c.foreground];
    };
  };
  programs.opencode.themes.flat-white = lib.mkIf (on "opencode") (import ./opencode.nix {inherit lib;});
  # HM 尚无 V2 cli 选项；官方 inline 配置可覆盖已经迁移过的 cli.json。
  home.sessionVariables.OPENCODE_CLI_CONFIG_CONTENT = lib.mkIf (on "opencode") (builtins.toJSON {
    theme = {
      name = "flat-white";
      mode = "dark";
    };
  });
  programs.codex.settings.tui.theme = lib.mkIf (on "codex") "flat-white";
  home.file.".codex/themes/flat-white.tmTheme" = lib.mkIf (on "codex") {source = tmTheme;};

  programs.claude-code.settings.theme = lib.mkIf (on "claude-code") "custom:flat-white";
  # 与 Codex 一样只合并声明的字段，保留 /model 等命令写回的运行时设置。
  home.file."${config.programs.claude-code.configDir}/settings.json" = lib.mkIf (on "claude-code") {enable = false;};
  home.activation.flatWhiteClaudeSettings = lib.mkIf (on "claude-code") (lib.hm.dag.entryAfter ["writeBoundary"] ''
    run ${pkgs.python3}/bin/python ${../pi/merge-settings.py} \
      ${lib.escapeShellArg "${config.programs.claude-code.configDir}/settings.json"} \
      ${lib.escapeShellArg (builtins.toJSON config.programs.claude-code.settings)}
  '');
  # 主题是资源；当前 HM 没有 Claude themes 选项。
  home.file.".claude/themes/flat-white.json" = lib.mkIf (on "claude-code") {
    text = builtins.toJSON {
      name = "Flat White";
      base = "dark-ansi";
      overrides = {
        claude = c.color3;
        claudeShimmer = c.color11;
        text = c.foreground;
        inverseText = c.background;
        inactive = c.color8;
        inactiveShimmer = c.cursor;
        subtle = c.selection_bg;
        suggestion = c.color4;
        permission = c.color5;
        permissionShimmer = c.color13;
        remember = c.color6;
        success = c.color2;
        error = c.color1;
        warning = c.color3;
        warningShimmer = c.color11;
        merged = c.color5;
        promptBorder = c.color4;
        promptBorderShimmer = c.color12;
        planMode = c.color6;
        autoAccept = c.color2;
        bashBorder = c.color5;
        ide = c.color4;
        fastMode = c.color3;
        fastModeShimmer = c.color11;
        effortUltra = c.color13;
        diffAdded = c.color0;
        diffRemoved = c.color0;
        diffAddedDimmed = c.background;
        diffRemovedDimmed = c.background;
        diffAddedWord = c.selection_bg;
        diffRemovedWord = c.selection_bg;
        userMessageBackground = c.color0;
        userMessageBackgroundHover = c.selection_bg;
        bashMessageBackgroundColor = c.color0;
        memoryBackgroundColor = c.color0;
        selectionBg = c.selection_bg;
        composerSidebarBackground = c.color0;
        rate_limit_fill = c.color4;
        rate_limit_empty = c.selection_bg;
        briefLabelYou = c.color4;
        briefLabelClaude = c.color3;
        red_FOR_SUBAGENTS_ONLY = c.color1;
        blue_FOR_SUBAGENTS_ONLY = c.color4;
        green_FOR_SUBAGENTS_ONLY = c.color2;
        yellow_FOR_SUBAGENTS_ONLY = c.color11;
        purple_FOR_SUBAGENTS_ONLY = c.color5;
        orange_FOR_SUBAGENTS_ONLY = c.color3;
        pink_FOR_SUBAGENTS_ONLY = c.color13;
        cyan_FOR_SUBAGENTS_ONLY = c.color6;
      };
    };
  };
  programs.vicinae = lib.mkIf (on "vicinae") {
    settings.theme = {
      dark.name = "flat-white";
      light.name = "flat-white";
    };
    themes.flat-white = {
      meta = {
        version = 1;
        name = "Flat White";
        variant = "dark";
        inherits = "vicinae-dark";
      };
      colors = {
        core = {
          inherit (c) background foreground;
          secondary_background = c.color0;
          border = c.selection_bg;
          accent = c.color4;
        };
        accents = {
          blue = c.color4;
          green = c.color2;
          magenta = c.color13;
          orange = c.color3;
          purple = c.color5;
          red = c.color1;
          yellow = c.color11;
          cyan = c.color6;
        };
      };
    };
  };
}
