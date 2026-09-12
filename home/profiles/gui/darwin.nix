{
  config,
  lib,
  pkgs,
  pkgs-unstable,
  ...
}: let
  # nixpkgs-unstable 已经滚到 26.11,那个分支不再支持 x86_64-darwin —— 一碰
  # pkgs-unstable 的任何包就 throw。hackintosh 只能从 26.05 里取,别的 Mac
  # 照旧吃 unstable 的新版本。见 docs/decisions.md#x86-64-darwin-unstable-drop。
  unstableOr =
    if pkgs.stdenv.hostPlatform.system == "x86_64-darwin"
    then pkgs
    else pkgs-unstable;
in {
  imports = [
    ../../modules/ghostty
  ];
  home.packages =
    (with pkgs; [
      swiftlint
      jdk
      # spotatui
      sioyek
      unstableOr.raycast
      # spotify
      # discord
      # harper
      # emacs
    ])
    ++ lib.optionals (config.my.host.name != "alex") [pkgs.wezterm];

  programs.zathura = {
    enable = false;
  };

  # services.ollama = {
  #   enable = true;
  #   package = pkgs-unstable.ollama;
  # };
}
