# Pi 没有原生 HM 模块，沿用该应用已有的可写 JSON 合并机制。
{
  config,
  lib,
  pkgs,
  ...
}: let
  c = (import ./palette.nix).colors;
in {
  home.activation.piTheme = lib.hm.dag.entryAfter ["writeBoundary"] ''
    run ${pkgs.python3}/bin/python ${../../../../../scripts/merge-json-settings.py} \
      ${lib.escapeShellArg "${config.home.homeDirectory}/.pi/agent/settings.json"} \
      ${lib.escapeShellArg (builtins.toJSON {theme = "flat-white";})}
  '';
  home.file.".pi/agent/themes/flat-white.json".text = builtins.toJSON {
    name = "flat-white";
    appearance = "dark";
    colors = {
      accent = c.color4;
      border = c.selection_bg;
      borderAccent = c.color4;
      borderMuted = c.color8;
      success = c.color2;
      error = c.color1;
      warning = c.color3;
      muted = c.color8;
      dim = c.color8;
      text = c.foreground;
      thinkingText = c.color8;
      selectedBg = c.selection_bg;
      userMessageBg = c.color0;
      userMessageText = c.foreground;
      customMessageBg = c.color0;
      customMessageText = c.foreground;
      customMessageLabel = c.color5;
      toolPendingBg = c.color0;
      toolSuccessBg = c.color0;
      toolErrorBg = c.color0;
      toolTitle = c.color4;
      toolOutput = c.foreground;
      mdHeading = c.color4;
      mdLink = c.color4;
      mdLinkUrl = c.color6;
      mdCode = c.color2;
      mdCodeBlock = c.foreground;
      mdCodeBlockBorder = c.color8;
      mdQuote = c.color8;
      mdQuoteBorder = c.color8;
      mdHr = c.color8;
      mdListBullet = c.color3;
      toolDiffAdded = c.color2;
      toolDiffRemoved = c.color1;
      toolDiffContext = c.foreground;
      syntaxComment = c.color8;
      syntaxKeyword = c.color3;
      syntaxFunction = c.color4;
      syntaxVariable = c.foreground;
      syntaxString = c.color2;
      syntaxNumber = c.color5;
      syntaxType = c.color6;
      syntaxOperator = c.color6;
      syntaxPunctuation = c.foreground;
      thinkingOff = c.color8;
      thinkingMinimal = c.color6;
      thinkingLow = c.color2;
      thinkingMedium = c.color4;
      thinkingHigh = c.color5;
      thinkingXhigh = c.color13;
      thinkingMax = c.color11;
      bashMode = c.color3;
    };
    export = {
      pageBg = c.background;
      cardBg = c.color0;
      infoBg = c.selection_bg;
    };
  };
}
