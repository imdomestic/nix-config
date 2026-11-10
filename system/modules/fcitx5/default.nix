{
  config,
  lib,
  pkgs,
  ...
}: {
  # desktop profile 带的输入法。GNOME 自己驱动 ibus,hank 在 268v / taipan / encore
  # 上用的就是它(引擎各自在 host 里配),那几台把这里设成 "ibus"。
  options.my.inputMethod = lib.mkOption {
    type = lib.types.enum ["fcitx5" "ibus"];
    default = "fcitx5";
    description = "Input method framework on this desktop host.";
  };

  config = lib.mkIf (config.my.inputMethod == "fcitx5") {
    i18n.inputMethod = {
      enable = true;
      type = "fcitx5";
    };
    i18n.inputMethod.fcitx5 = {
      waylandFrontend = true;
      addons = with pkgs; [
        qt6Packages.fcitx5-chinese-addons
        fcitx5-pinyin-zhwiki
        (fcitx5-rime.override {
          rimeDataPkgs = [
            rime-data
            rime-ice
          ];
        })
        fcitx5-mozc
        fcitx5-gtk # Fcitx5 gtk im module and glib based dbus client library
        qt6Packages.fcitx5-qt
        fcitx5-material-color
        catppuccin-fcitx5
      ];
      settings = {
        addons = {
          pinyin.globalSection = {
            PageSize = 9;
            CloudPinyinEnabled = "True";
            CloudPinyinIndex = 2;
          };
          cloudpinyin.globalSection = {
            Backend = "Baidu";
          };
          classicui.globalSection = {
            Theme = "Material-Color-teal";
          };
        };
        globalOptions = {
          "Hotkey/TriggerKeys" = {
            "0" = "Control+space";
          };
        };
        inputMethod = {
          "Groups/0" = {
            Name = "Default";
            "Default Layout" = "us";
            DefaultIM = "keyboard-us";
          };
          "Groups/0/Items/0".Name = "keyboard-us";
          "Groups/0/Items/1".Name = "pinyin";
          "Groups/0/Items/2".Name = "rime";
          GroupOrder."0" = "Default";
        };
      };
    };

    environment.systemPackages = [
      pkgs.qt6Packages.fcitx5-configtool
    ];

    environment.sessionVariables = {
      XMODIFIERS = "@im=fcitx";
      QT_IM_MODULE = "fcitx";
    };
  };
}
