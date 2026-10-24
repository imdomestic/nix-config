{
  config,
  lib,
  ...
}: let
  c = (import ./palette.nix).colors;
in {
  programs.vicinae = lib.mkIf config.programs.vicinae.enable {
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
