{lib, ...}: {
  dconf.settings = {
    "org/gnome/desktop/input-sources".sources = [
      (lib.hm.gvariant.mkTuple ["xkb" "us"])
      (lib.hm.gvariant.mkTuple ["ibus" "libpinyin"])
    ];
    "org/gnome/desktop/wm/keybindings" = {
      switch-input-source = ["<Control><Alt>space"];
      switch-input-source-backward = ["<Control>space"];
    };
    "com/github/libpinyin/ibus-libpinyin/libpinyin" = {
      double-pinyin = true;
      # ibus-libpinyin identifies Xiaohe (XHE) with schema index 5.
      double-pinyin-schema = 5;
      # Use GNOME's source shortcuts instead of a second Shift-only mode switch.
      main-switch = "";
      minus-equal-page = true;
      square-bracket-page = true;
      comma-period-page = false;
    };
  };
}
