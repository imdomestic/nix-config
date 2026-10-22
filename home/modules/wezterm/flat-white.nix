{
  config,
  lib,
  ...
}: let
  palette = import ../palettes/flat-white.nix;
  c = palette.colors;
in {
  programs.wezterm = lib.mkIf config.programs.wezterm.enable {
    settings.color_scheme = "flat-white";
    colorSchemes.flat-white = {
      inherit (c) background foreground selection_bg selection_fg;
      cursor_bg = c.cursor;
      cursor_fg = c.cursor_text;
      cursor_border = c.cursor;
      ansi = lib.take 8 palette.ansi;
      brights = lib.drop 8 palette.ansi;
    };
  };
}
