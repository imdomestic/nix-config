{
  pkgs,
  lib,
  config,
  ...
}: {
  home.packages = lib.mkIf (config.my.host.name == "b650") (with pkgs; [
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
  ]);
}
