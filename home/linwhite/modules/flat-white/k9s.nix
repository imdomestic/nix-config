{
  config,
  lib,
  ...
}: let
  c = (import ./palette.nix).colors;
in {
  programs.k9s = lib.mkIf config.programs.k9s.enable {
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
}
