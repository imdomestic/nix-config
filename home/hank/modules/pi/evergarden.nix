# Palette/theme roles: evergardentheme/nvim@c8e5e7e67a36694e5d917b7065b26b59b8cb489f, lua/evergarden/.
let
  winter = (import ../palettes/evergarden-winter.nix).colors;
  palettes = {
    evergarden-winter = winter;
    evergarden-fall =
      winter
      // {
        surface0 = "#2b3337";
        base = "#232a2e";
        mantle = "#1c2225";
        # 上游 DiffAdd/Delete 是前景与 base 的 16% blend；Winter 保留既有底色。
        diffAddBg = "#3e4843";
        diffDelBg = "#45383b";
      };
    evergarden-spring =
      winter
      // {
        surface1 = "#3e4a4f";
        surface0 = "#343e43";
        base = "#2b3438";
        mantle = "#232a2e";
        crust = "#1c2225";
        diffAddBg = "#45504c";
        diffDelBg = "#4b4044";
      };
    evergarden-summer = {
      red = "#c58687";
      orange = "#c69883";
      yellow = "#c4aa80";
      lime = "#abb182";
      green = "#91a77a";
      aqua = "#74a48b";
      skye = "#719f96";
      snow = "#7799a3";
      blue = "#8294ad";
      purple = "#a897b8";
      pink = "#c499b8";
      cherry = "#c29fb2";
      text = "#2b3034";
      subtext1 = "#455355";
      subtext0 = "#576869";
      overlay2 = "#707d76";
      overlay1 = "#829084";
      overlay0 = "#acb5a4";
      surface2 = "#ceccbd";
      surface1 = "#e6e1d3";
      surface0 = "#ede8dd";
      base = "#f5efe6";
      mantle = "#f2eae1";
      crust = "#e8ded5";
      diffAddBg = "#e5e3d5";
      diffDelBg = "#edded7";
    };
    # Lunar 已有独立上游 palette，但尚未列入 README 的四季预览。
    evergarden-lunar = {
      red = "#EB7F86";
      orange = "#F5A58D";
      yellow = "#F7DDAF";
      lime = "#DBE3C7";
      green = "#C5D9B5";
      aqua = "#ACD1B6";
      skye = "#AAD0C9";
      snow = "#ADD1D8";
      blue = "#99B3D5";
      purple = "#A69FD5";
      pink = "#D6ABC3";
      cherry = "#E0C5D0";
      text = "#F7F1E6";
      subtext1 = "#CBD7F2";
      subtext0 = "#B4C0DB";
      overlay2 = "#9EA5C1";
      overlay1 = "#9096B1";
      overlay0 = "#757A93";
      surface2 = "#4C4F61";
      surface1 = "#353847";
      surface0 = "#21232E";
      base = "#1C1D29";
      mantle = "#171923";
      crust = "#11121A";
      diffAddBg = "#373b3f";
      diffDelBg = "#3d2d38";
    };
  };
in
  builtins.mapAttrs (name: c: {
    "$schema" = "https://pi.dev/schemas/theme.schema.json";
    inherit name;
    appearance =
      if name == "evergarden-summer"
      then "light"
      else "dark";
    colors = with c; {
      accent = green;
      border = overlay1;
      borderAccent = lime;
      borderMuted = surface2;
      success = green;
      error = red;
      warning = yellow;
      muted = subtext0;
      dim = overlay1;
      inherit text;
      thinkingText = overlay2;

      selectedBg = surface1;
      scrollbarTrack = overlay1;
      scrollbarThumb = overlay2;
      searchMatchBg = surface1;
      searchMatchText = text;
      userMessageBg = surface0;
      userMessageText = text;
      customMessageBg = surface0;
      customMessageText = text;
      customMessageLabel = purple;
      toolPendingBg = surface0;
      toolSuccessBg = diffAddBg;
      toolErrorBg = diffDelBg;
      toolTitle = text;
      toolOutput = text;

      mdHeading = green;
      mdLink = blue;
      mdLinkUrl = subtext0;
      mdCode = lime;
      mdCodeBlock = lime;
      mdCodeBlockBorder = overlay1;
      mdQuote = overlay2;
      mdQuoteBorder = overlay1;
      mdHr = overlay1;
      mdListBullet = aqua;
      toolDiffAdded = green;
      toolDiffRemoved = red;
      toolDiffContext = subtext0;

      syntaxComment = overlay2;
      syntaxKeyword = red;
      syntaxFunction = green;
      syntaxVariable = text;
      syntaxString = lime;
      syntaxNumber = pink;
      syntaxType = yellow;
      syntaxOperator = subtext0;
      syntaxPunctuation = overlay1;
      thinkingOff = overlay0;
      thinkingMinimal = overlay2;
      thinkingLow = snow;
      thinkingMedium = blue;
      thinkingHigh = purple;
      thinkingXhigh = pink;
      thinkingMax = red;
      bashMode = green;
    };
    export = with c; {
      pageBg = base;
      cardBg = mantle;
      infoBg = surface1;
    };
  })
  palettes
