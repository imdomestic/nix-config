{lib, ...}: {
  dconf.settings = {
    "org/gnome/desktop/input-sources".sources = [
      (lib.hm.gvariant.mkTuple ["xkb" "us"])
      (lib.hm.gvariant.mkTuple ["ibus" "libpinyin"])
    ];
    "com/github/libpinyin/ibus-libpinyin/libpinyin" = {
      double-pinyin = true;
      # ibus-libpinyin identifies Xiaohe (XHE) with schema index 5.
      double-pinyin-schema = 5;
    };
  };
}
