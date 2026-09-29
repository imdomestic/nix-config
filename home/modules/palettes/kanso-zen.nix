# 不是模块,是被 claude-code / opencode 等 import 的数据。
# colors 是 kanso.nvim lua/kanso/colors.lua 里 zen 用得到的那部分;ghostty 的 kanso 也是 zen。
let
  colors = {
    zenBg0 = "#090E13";
    zenBg1 = "#1C1E25";
    zenBg2 = "#22262D";
    zenBg3 = "#393B44";

    diffGreen = "#2B3328";
    diffRed = "#43242B";
    gitGreen = "#76946A";
    gitRed = "#C34043";

    red = "#C34043";
    red3 = "#c4746e";
    yellow = "#DCA561";
    yellow2 = "#E6C384";
    yellow3 = "#c4b28a";
    green = "#98BB6C";
    green3 = "#8a9a7b";
    blue = "#7FB4CA";
    blue2 = "#658594";
    blue3 = "#8ba4b0";
    violet = "#938AA9";
    violet2 = "#8992a7";
    pink = "#a292a3";
    orange = "#b6927b";
    aqua = "#8ea4a2";

    fg = "#C5C9C7";
    gray2 = "#A4A7A4";
    gray3 = "#909398";
    gray4 = "#75797f";
    gray5 = "#5C6066";
  };
in {
  inherit colors;
  name = "Kanso Zen";

  # 与 evergarden-winter.nix 同一组角色名;取色依据 kanso 的 themes.lua(zen)。
  roles = with colors; {
    accent = blue3;
    accentShimmer = blue;
    inherit fg;
    muted = gray4;
    faint = zenBg3;
    border = gray5;
    bg = zenBg0;
    bgRaised = zenBg2;
    bgHover = zenBg3;

    error = red;
    warning = yellow;
    warningShimmer = yellow2;
    success = green;

    # 终端 ANSI 那组,比 diag 的颜色柔和。
    red = red3;
    yellow = yellow3;
    green = green3;
    cyan = aqua;
    blue = blue3;
    purple = violet;
    inherit orange pink;
  };
}
