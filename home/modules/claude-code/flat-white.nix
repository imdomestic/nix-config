{
  config,
  lib,
  ...
}: let
  c = (import ../palettes/flat-white.nix).colors;
in {
  config = lib.mkIf config.programs.claude-code.enable {
    programs.claude-code.settings.theme = "custom:flat-white";
    # 主题是资源；当前 HM 没有 Claude themes 选项。
    home.file."${config.programs.claude-code.configDir}/themes/flat-white.json".text = builtins.toJSON {
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
}
