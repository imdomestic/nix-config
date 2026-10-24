# 不是模块,是被 claude-code / opencode 等 import 的数据。
# colors 抄自 evergarden-nvim 的 lua/evergarden/palettes/winter.lua,与 nixvim 同一套(winter / green)。
let
  colors = {
    red = "#f57f82";
    orange = "#f7a182";
    yellow = "#f5d098";
    lime = "#dbe6af";
    green = "#cbe3b3";
    aqua = "#b3e3ca";
    skye = "#b3e6db";
    snow = "#afd9e6";
    blue = "#b2caed";
    purple = "#d2bdf3";
    pink = "#f3c0e5";
    cherry = "#fae6ef";
    text = "#f8f9e8";
    subtext1 = "#adc9bc";
    subtext0 = "#96b4aa";
    overlay2 = "#839e9a";
    overlay1 = "#6f8788";
    overlay0 = "#58686d";
    surface2 = "#4a585c";
    surface1 = "#374145";
    surface0 = "#262f33";
    base = "#1e2528";
    mantle = "#191e21";
    crust = "#171c1f";

    # winter.lua 里没有 diff 底色,沿用 opencode 主题原先的值。
    diffAddBg = "#36403b";
    diffDelBg = "#3c3235";
    diffAddWord = "#4e5a4f";
    diffDelWord = "#5a3e41";
  };
in {
  inherit colors;
  name = "Evergarden Winter";

  # 各调色板共用的角色名,不关心上游怎么叫。
  roles = with colors; {
    accent = green;
    accentShimmer = lime;
    fg = text;
    muted = overlay2;
    faint = surface2;
    border = overlay1;
    bg = base;
    bgRaised = surface0;
    bgHover = surface1;

    error = red;
    warning = yellow;
    warningShimmer = text;
    success = green;

    inherit red orange yellow green blue purple pink;
    cyan = skye;
  };
}
