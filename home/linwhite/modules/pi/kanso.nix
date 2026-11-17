# Palette/theme roles: webhooked/kanso.nvim@1afbbb449aa0254823dbe1932e3cbb51886ff9fe, lua/kanso/.
let
  dark = (import ../palettes/kanso-zen.nix).colors;
  palettes = {
    kanso-zen =
      dark
      // {
        bg0 = dark.zenBg0;
        bg1 = dark.zenBg1;
        bg2 = dark.zenBg2;
        bg3 = dark.zenBg3;
      };
    kanso-ink =
      dark
      // {
        bg0 = "#14171d";
        bg1 = "#1f1f26";
        bg2 = "#22262D";
        bg3 = "#393B44";
      };
    kanso-mist =
      dark
      // {
        bg0 = "#22262D";
        bg1 = "#2a2c35";
        bg2 = "#393B44";
        bg3 = "#393B44";
      };
    # Pearl 使用上游独立的浅色前景、诊断和 diff palette，不反转暗色主题。
    kanso-pearl = {
      bg0 = "#f2f1ef";
      bg1 = "#e2e1df";
      bg2 = "#e2e1df";
      bg3 = "#dddddb";
      fg = "#22262D";
      gray2 = "#545464";
      gray3 = "#6D6D69";
      gray4 = "#6D6D69";
      gray5 = "#9F9F99";
      red = "#e82424";
      red3 = "#c84053";
      yellow = "#e98a00";
      yellow2 = "#836f4a";
      yellow3 = "#77713f";
      green = "#6f894e";
      green3 = "#6f894e";
      blue = "#6693bf";
      blue2 = "#5a7785";
      blue3 = "#4d699b";
      violet = "#624c83";
      violet2 = "#624c83";
      pink = "#b35b79";
      aqua = "#597b75";
      diffGreen = "#b7d0ae";
      diffRed = "#d9a594";
      gitGreen = "#6e915f";
      gitRed = "#d7474b";
    };
  };
in
  builtins.mapAttrs (name: c: let
    light = name == "kanso-pearl";
  in {
    "$schema" = "https://pi.dev/schemas/theme.schema.json";
    inherit name;
    appearance =
      if light
      then "light"
      else "dark";
    colors = with c; {
      accent = blue3;
      border = gray5;
      borderAccent = blue;
      borderMuted = bg3;
      success = green;
      error = red;
      warning = yellow;
      muted = gray2;
      dim = gray4;
      text = fg;
      thinkingText = gray3;

      selectedBg = bg3;
      scrollbarTrack = gray5;
      scrollbarThumb = gray3;
      searchMatchBg = bg3;
      searchMatchText = yellow2;
      userMessageBg = bg2;
      userMessageText = fg;
      customMessageBg = bg1;
      customMessageText = fg;
      customMessageLabel = violet;
      toolPendingBg = bg1;
      toolSuccessBg = diffGreen;
      toolErrorBg = diffRed;
      toolTitle = fg;
      toolOutput = fg;

      mdHeading = violet2;
      mdLink = blue3;
      mdLinkUrl = gray2;
      mdCode = green3;
      mdCodeBlock = green3;
      mdCodeBlockBorder = gray5;
      mdQuote = gray2;
      mdQuoteBorder = gray5;
      mdHr = gray5;
      mdListBullet = yellow3;
      toolDiffAdded = gitGreen;
      toolDiffRemoved =
        if light
        then gitRed
        else red3;
      toolDiffContext = gray2;

      syntaxComment = gray4;
      syntaxKeyword = violet2;
      syntaxFunction = blue3;
      syntaxVariable = fg;
      syntaxString = green3;
      syntaxNumber = pink;
      syntaxType = aqua;
      syntaxOperator = gray3;
      syntaxPunctuation = gray3;
      thinkingOff = gray5;
      thinkingMinimal = gray3;
      thinkingLow = blue2;
      thinkingMedium = blue3;
      thinkingHigh = violet2;
      thinkingXhigh = violet;
      thinkingMax = pink;
      bashMode = green3;
    };
    export = with c; {
      pageBg = bg0;
      cardBg = bg1;
      infoBg = bg2;
    };
  })
  palettes
