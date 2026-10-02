{
  config,
  lib,
  pkgs,
  ...
}: {
  imports = [../../modules/ghostty];

  home.packages =
    (with pkgs; [
      swiftlint
      jdk
      sioyek
    ])
    ++ lib.optionals (config.my.host.name != "alex") [pkgs.wezterm];

  programs.zathura.enable = false;
}
