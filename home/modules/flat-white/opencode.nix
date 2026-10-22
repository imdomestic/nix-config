{lib}: let
  c = (import ../palettes/flat-white.nix).colors;
  scale = bright: normal:
    builtins.listToAttrs (lib.imap0 (i: value: {
      name = toString ((i + 1) * 100);
      inherit value;
    }) [bright normal normal normal c.color8 c.selection_bg c.background c.color0 c.color0]);
  feedback = {
    error = c.color1;
    warning = c.color3;
    success = c.color2;
    info = c.color6;
  };
in {
  # V2 完整 token 树；不依赖 V1 迁移或某个内置主题的默认值。
  base = {
    categorical = ["blue" "purple" "green" "orange" "cyan" "red"];
    text = {
      base = c.foreground;
      muted = c.color8;
      action = {
        primary = {
          base = c.color4;
          "$focused" = c.background;
          "$selected" = c.color12;
        };
        secondary.base = c.foreground;
        destructive.base = c.color1;
      };
      formfield = {
        base = c.foreground;
        "$disabled" = c.color8;
      };
      feedback = lib.mapAttrs (_: color: {base = color;}) feedback;
    };
    background = {
      base = c.background;
      raised = {
        base = c.color0;
        high = c.selection_bg;
        max = c.color8;
      };
      action = {
        primary = {
          base = "transparent";
          "$hovered" = c.selection_bg;
          "$focused" = c.color4;
        };
        secondary = {
          base = "transparent";
          "$hovered" = c.selection_bg;
        };
        destructive = {
          base = c.color0;
          "$hovered" = c.selection_bg;
        };
      };
      formfield.base = c.color0;
      feedback = lib.mapAttrs (_: _: {base = c.color0;}) feedback;
    };
    border.base = c.selection_bg;
    scrollbar.base = c.color8;
    diff = {
      text = {
        added = c.color2;
        removed = c.color1;
        context = c.foreground;
        hunkHeader = c.color6;
      };
      background = {
        added = c.color0;
        removed = c.color0;
        context = c.background;
      };
      highlight = {
        added = c.color2;
        removed = c.color1;
      };
      lineNumber = {
        text = c.color8;
        background = {
          added = c.color0;
          removed = c.color0;
        };
      };
    };
    syntax = {
      comment = c.color8;
      keyword = c.color3;
      function = c.color4;
      variable = c.foreground;
      string = c.color2;
      number = c.color5;
      type = c.color6;
      operator = c.color6;
      punctuation = c.foreground;
    };
    markdown = {
      text = c.foreground;
      heading = c.color4;
      link = c.color4;
      linkText = c.color6;
      code = c.color2;
      blockQuote = c.color8;
      emphasis = c.color3;
      strong = c.color5;
      horizontalRule = c.color8;
      listItem = c.color4;
      listEnumeration = c.color6;
      image = c.color4;
      imageText = c.color6;
      codeBlock = c.color2;
    };
    "@dialog".background.base = c.color0;
  };
  dark.hue = {
    gray = scale c.color15 c.foreground;
    red = scale c.color9 c.color1;
    orange = scale c.color11 c.color3;
    yellow = scale c.color11 c.color3;
    green = scale c.color10 c.color2;
    cyan = scale c.color14 c.color6;
    blue = scale c.color12 c.color4;
    purple = scale c.color13 c.color5;
    accent = "$hue.orange";
    interactive = "$hue.blue";
    neutral = "$hue.gray";
  };
}
