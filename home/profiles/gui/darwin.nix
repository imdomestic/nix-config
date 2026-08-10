{
  config,
  lib,
  pkgs,
  pkgs-unstable,
  ...
}: {
  imports = [
    ../../modules/kitty
    ../../modules/ghostty
  ];
  home.packages =
    (with pkgs; [
      swiftlint
      jdk
      # spotatui
      sioyek
      pkgs-unstable.raycast
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
