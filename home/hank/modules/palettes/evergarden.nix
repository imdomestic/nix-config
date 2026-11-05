# Palette/theme roles: evergardentheme/nvim@c8e5e7e67a36694e5d917b7065b26b59b8cb489f, lua/evergarden/.
let
  winter = {
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
  palettes = {
    evergarden-winter = winter;
    evergarden-fall =
      winter
      // {
        surface0 = "#2b3337";
        base = "#232a2e";
        mantle = "#1c2225";
        # 上游 DiffAdd/Delete 是前景与 base 的 16% blend；Winter 保留既有底色。
        diffAddBg = "#3e4843";
        diffDelBg = "#45383b";
      };
    evergarden-spring =
      winter
      // {
        surface1 = "#3e4a4f";
        surface0 = "#343e43";
        base = "#2b3438";
        mantle = "#232a2e";
        crust = "#1c2225";
        diffAddBg = "#45504c";
        diffDelBg = "#4b4044";
      };
    evergarden-summer = {
      red = "#c58687";
      orange = "#c69883";
      yellow = "#c4aa80";
      lime = "#abb182";
      green = "#91a77a";
      aqua = "#74a48b";
      skye = "#719f96";
      snow = "#7799a3";
      blue = "#8294ad";
      purple = "#a897b8";
      pink = "#c499b8";
      cherry = "#c29fb2";
      text = "#2b3034";
      subtext1 = "#455355";
      subtext0 = "#576869";
      overlay2 = "#707d76";
      overlay1 = "#829084";
      overlay0 = "#acb5a4";
      surface2 = "#ceccbd";
      surface1 = "#e6e1d3";
      surface0 = "#ede8dd";
      base = "#f5efe6";
      mantle = "#f2eae1";
      crust = "#e8ded5";
      diffAddBg = "#e5e3d5";
      diffDelBg = "#edded7";
    };
    # Lunar 已有独立上游 palette，但尚未列入 README 的四季预览。
    evergarden-lunar = {
      red = "#EB7F86";
      orange = "#F5A58D";
      yellow = "#F7DDAF";
      lime = "#DBE3C7";
      green = "#C5D9B5";
      aqua = "#ACD1B6";
      skye = "#AAD0C9";
      snow = "#ADD1D8";
      blue = "#99B3D5";
      purple = "#A69FD5";
      pink = "#D6ABC3";
      cherry = "#E0C5D0";
      text = "#F7F1E6";
      subtext1 = "#CBD7F2";
      subtext0 = "#B4C0DB";
      overlay2 = "#9EA5C1";
      overlay1 = "#9096B1";
      overlay0 = "#757A93";
      surface2 = "#4C4F61";
      surface1 = "#353847";
      surface0 = "#21232E";
      base = "#1C1D29";
      mantle = "#171923";
      crust = "#11121A";
      diffAddBg = "#373b3f";
      diffDelBg = "#3d2d38";
    };
  };
  names = {
    evergarden-winter = "Evergarden Winter";
    evergarden-fall = "Evergarden Fall";
    evergarden-spring = "Evergarden Spring";
    evergarden-summer = "Evergarden Summer";
    evergarden-lunar = "Evergarden Lunar";
  };
in
  builtins.mapAttrs (slug: colors: {
    inherit colors;
    name = names.${slug};
    appearance =
      if slug == "evergarden-summer"
      then "light"
      else "dark";

    # 各应用共用的角色名,不关心上游怎么叫。
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
  })
  palettes
