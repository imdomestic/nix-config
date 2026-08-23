{
  pkgs,
  lib,
  config,
  ...
}: let
  host = config.my.host.name;
  # 引了 gui.linux 的机器里,这三台是当桌面在用的 AMD 机。下面这组包原本躺在
  # 各自的 environment.systemPackages 里 —— 它们是人看的、人点的,机器自己一个
  # 都不需要,却要 root + 整机重建才能改。
  #
  # tank 也有图形界面,但它的 hank **没有**引 gui.linux(tank/default.nix 里那行
  # 是注释掉的),所以这个模块根本到不了 tank。它那几个桌面包挂在
  # home/users/hank/default.nix 的 host 条件里。
  amdWorkstations = ["b650" "gpd" "m16"];
in {
  home.packages = with pkgs;
    lib.optionals (host == "b650") [
      blueman
      spotify
      nix-output-monitor
      # nur.repos.xddxdd.baidunetdisk
      # nur.repos.nltch.spotify-adblock
      # nur.repos.novel2430.wechat-universal-bwrap
      # jetbrains.idea-ultimate
      android-tools
      telegram-desktop
      wkhtmltopdf
      minicom
      # code-cursor
      obs-studio
      qq
      vlc
      wezterm
      nautilus
    ]
    ++ lib.optionals (builtins.elem host amdWorkstations) [
      firefox
      clapper
      # GPU 占用率 / 调频 / 带 ROCm 的 btop。三台都是 AMD。
      radeontop
      corectrl
      btop-rocm
      # noctalia 不在这儿:它由 modules/noctalia 的 programs.noctalia-shell
      # 装,那边同时会写配置、起 user service。
    ];
}
