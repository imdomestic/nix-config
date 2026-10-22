{
  config,
  lib,
  ...
}: let
  c = (import ../palettes/flat-white.nix).colors;
in {
  programs.fzf.colors = lib.mkIf config.programs.fzf.enable {
    bg = c.background;
    fg = c.foreground;
    hl = c.color3;
    "bg+" = c.selection_bg;
    "fg+" = c.selection_fg;
    "hl+" = c.color11;
    border = c.color8;
    header = c.color4;
    gutter = c.background;
    info = c.color8;
    pointer = c.color3;
    marker = c.color2;
    prompt = c.color4;
    spinner = c.color5;
  };
}
