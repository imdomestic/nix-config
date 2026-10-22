{
  config,
  lib,
  ...
}: let
  c = (import ../palettes/flat-white.nix).colors;
in {
  programs.starship.settings = lib.mkIf config.programs.starship.enable {
    palette = "flat-white";
    palettes.flat-white = {
      black = c.color0;
      red = c.color1;
      green = c.color2;
      yellow = c.color3;
      blue = c.color4;
      purple = c.color5;
      cyan = c.color6;
      white = c.color7;
      "bright-black" = c.color8;
      "bright-red" = c.color9;
      "bright-green" = c.color10;
      "bright-yellow" = c.color11;
      "bright-blue" = c.color12;
      "bright-purple" = c.color13;
      "bright-cyan" = c.color14;
      "bright-white" = c.color15;
      bg = c.background;
      fg = c.foreground;
      muted = c.color8;
    };
  };
}
