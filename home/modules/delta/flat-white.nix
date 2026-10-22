{
  config,
  lib,
  ...
}: let
  c = (import ../palettes/flat-white.nix).colors;
in {
  programs.delta.options = lib.mkIf config.programs.delta.enable {
    dark = true;
    syntax-theme = "flat-white";
    minus-style = "syntax ${c.color0}";
    plus-style = "syntax ${c.color0}";
    minus-emph-style = "${c.color9} ${c.selection_bg}";
    plus-emph-style = "${c.color10} ${c.selection_bg}";
    line-numbers-minus-style = c.color1;
    line-numbers-plus-style = c.color2;
    line-numbers-zero-style = c.color8;
    file-style = "${c.color4} bold";
    file-decoration-style = c.color4;
    hunk-header-style = "file line-number syntax";
    hunk-header-decoration-style = c.color8;
  };
}
