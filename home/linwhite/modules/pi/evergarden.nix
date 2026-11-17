let
  palettes = import ../palettes/evergarden.nix;
in
  builtins.mapAttrs (name: pal: {
    "$schema" = "https://pi.dev/schemas/theme.schema.json";
    inherit name;
    inherit (pal) appearance;
    colors = with pal.colors; {
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
    export = with pal.colors; {
      pageBg = base;
      cardBg = mantle;
      infoBg = surface1;
    };
  })
  palettes
