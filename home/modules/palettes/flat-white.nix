# 不是模块，是基于 Espresso 的 Flat White 色卡；终端与工具共用这一份数据。
let
  colors = {
    background = "#323232";
    foreground = "#eeeeec";
    cursor = "#d6d6d6";
    cursor_text = "#323232";
    selection_bg = "#5b5b5b";
    selection_fg = "#eeeeec";

    color0 = "#1f1f1f";
    color1 = "#d25252";
    color2 = "#a5c261";
    color3 = "#ffc66d";
    color4 = "#6c99bb";
    color5 = "#d197d9";
    color6 = "#7fc8c8";
    color7 = "#eeeeec";
    color8 = "#7c7c7c";
    color9 = "#e86f6f";
    color10 = "#c2e075";
    color11 = "#e1e48b";
    color12 = "#8ab7d9";
    color13 = "#efb5f7";
    color14 = "#a8e0e0";
    color15 = "#ffffff";
  };
in {
  name = "Flat White";
  inherit colors;
  ansi = builtins.genList (i: colors."color${toString i}") 16;
}
