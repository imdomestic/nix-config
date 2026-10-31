# Pi 没有 HM 主题选项；复用 Hank 的调色板，JSON 由 default.nix 生成。
let
  evergarden = import ../palettes/evergarden-winter.nix;
  kanso = import ../palettes/kanso-zen.nix;
  mkTheme = name: palette: overrides: let
    r = palette.roles;
  in {
    "$schema" = "https://pi.dev/schemas/theme.schema.json";
    inherit name;
    appearance = "dark";
    colors =
      {
        accent = r.accent;
        border = r.border;
        borderAccent = r.accentShimmer;
        borderMuted = r.faint;
        success = r.success;
        error = r.error;
        warning = r.warning;
        muted = r.muted;
        dim = r.border;
        text = r.fg;
        thinkingText = r.muted;

        selectedBg = r.bgHover;
        scrollbarTrack = r.border;
        scrollbarThumb = r.muted;
        searchMatchBg = r.bgHover;
        searchMatchText = r.warningShimmer;
        userMessageBg = r.bgRaised;
        userMessageText = r.fg;
        customMessageBg = r.bgRaised;
        customMessageText = r.fg;
        customMessageLabel = r.purple;
        toolPendingBg = r.bgRaised;
        toolTitle = r.fg;
        toolOutput = r.fg;

        mdLink = r.blue;
        mdLinkUrl = r.muted;
        mdCodeBlockBorder = r.border;
        mdQuote = r.muted;
        mdQuoteBorder = r.border;
        mdHr = r.border;
        mdListBullet = r.cyan;
        toolDiffAdded = r.success;
        toolDiffRemoved = r.red;
        toolDiffContext = r.muted;
        syntaxVariable = r.fg;
        syntaxNumber = r.pink;
        bashMode = r.green;
      }
      // overrides.colors;
    export =
      {
        pageBg = r.bg;
        cardBg = r.bgRaised;
        infoBg = r.bgHover;
      }
      // (overrides.export or {});
  };
in {
  evergarden-winter = mkTheme "evergarden-winter" evergarden {
    colors = with evergarden.colors; {
      muted = subtext0;
      dim = overlay1;
      thinkingText = overlay2;
      toolSuccessBg = diffAddBg;
      toolErrorBg = diffDelBg;
      mdHeading = green;
      mdLinkUrl = subtext0;
      mdCode = lime;
      mdCodeBlock = lime;
      mdQuote = overlay2;
      mdListBullet = aqua;
      toolDiffContext = subtext0;

      # 与 nixvim / opencode 的 Evergarden Winter 高亮角色保持一致。
      syntaxComment = overlay2;
      syntaxKeyword = red;
      syntaxFunction = green;
      syntaxString = lime;
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
    };
    export.cardBg = evergarden.colors.mantle;
  };
  kanso-zen = mkTheme "kanso-zen" kanso {
    colors = with kanso.colors; {
      muted = gray2;
      dim = gray4;
      thinkingText = gray3;
      scrollbarThumb = gray3;
      customMessageBg = zenBg1;
      toolPendingBg = zenBg1;
      toolSuccessBg = diffGreen;
      toolErrorBg = diffRed;
      mdHeading = violet2;
      mdLinkUrl = gray2;
      mdCode = green3;
      mdCodeBlock = green3;
      mdQuote = gray2;
      mdListBullet = yellow3;
      toolDiffAdded = gitGreen;
      toolDiffRemoved = red3;
      toolDiffContext = gray2;

      # 与 kanso.nvim 的 Zen 变体及现有 opencode 配色保持一致。
      syntaxComment = gray4;
      syntaxKeyword = violet2;
      syntaxFunction = blue3;
      syntaxString = green3;
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
    };
    export = with kanso.colors; {
      cardBg = zenBg1;
      infoBg = zenBg2;
    };
  };
}
