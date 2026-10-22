{
  config,
  lib,
  pkgs,
  ...
}: let
  c = (import ../palettes/flat-white.nix).colors;
in {
  config = lib.mkIf config.my.nixvim.dev.enable {
    # pi 尚无 HM 模块，沿用仓库已有的可写 JSON 合并器。
    home.activation.flatWhitePi = lib.hm.dag.entryAfter ["writeBoundary"] ''
      run ${pkgs.python3}/bin/python ${../pi/merge-settings.py} \
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
    programs.k9s = {
      enable = true;
      settings.k9s.ui.skin = "flat-white";
      skins.flat-white.k9s = {
        body = {
          fgColor = c.foreground;
          bgColor = c.background;
          logoColor = c.color4;
        };
        prompt = {
          fgColor = c.foreground;
          bgColor = c.color0;
          suggestColor = c.color6;
        };
        info = {
          fgColor = c.color4;
          sectionColor = c.color3;
        };
        frame = {
          border = {
            fgColor = c.color8;
            focusColor = c.color4;
          };
          menu = {
            fgColor = c.foreground;
            keyColor = c.color4;
            numKeyColor = c.color5;
          };
          crumbs = {
            fgColor = c.background;
            bgColor = c.color4;
            activeColor = c.color3;
          };
          status = {
            newColor = c.color2;
            modifyColor = c.color3;
            addColor = c.color2;
            errorColor = c.color1;
            highlightColor = c.color4;
            killColor = c.color8;
            completedColor = c.color6;
          };
          title = {
            fgColor = c.foreground;
            bgColor = c.color0;
            highlightColor = c.color4;
            counterColor = c.color5;
            filterColor = c.color3;
          };
        };
        views = {
          charts = {
            bgColor = c.background;
            defaultDialColors = [c.color4 c.color1];
            defaultChartColors = [c.color4 c.color2];
          };
          table = {
            fgColor = c.foreground;
            bgColor = c.background;
            cursorFgColor = c.selection_fg;
            cursorBgColor = c.selection_bg;
            header = {
              fgColor = c.color4;
              bgColor = c.color0;
              sorterColor = c.color3;
            };
          };
          xray = {
            fgColor = c.foreground;
            bgColor = c.background;
            cursorColor = c.color4;
            graphicColor = c.color6;
            showIcons = true;
          };
          yaml = {
            keyColor = c.color4;
            colonColor = c.color8;
            valueColor = c.color2;
          };
          logs = {
            fgColor = c.foreground;
            bgColor = c.background;
            indicator = {
              fgColor = c.foreground;
              bgColor = c.color0;
            };
          };
        };
      };
    };
  };
}
