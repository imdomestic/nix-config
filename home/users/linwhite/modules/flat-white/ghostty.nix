{
  config,
  lib,
  ...
}: let
  palette = import ./palette.nix;
  c = palette.colors;
in {
  programs.ghostty = lib.mkIf config.programs.ghostty.enable {
    settings.theme = "flat-white";
    themes.flat-white = {
      inherit (c) background foreground;
      cursor-color = c.cursor;
      cursor-text = c.cursor_text;
      selection-background = c.selection_bg;
      selection-foreground = c.selection_fg;
      palette = lib.imap0 (i: color: "${toString i}=${color}") palette.ansi;
    };
  };
}
