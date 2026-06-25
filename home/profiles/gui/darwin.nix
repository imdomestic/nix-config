{
  pkgs,
  pkgs-unstable,
  ...
}: {
  imports = [
    ../../modules/kitty
    ../../modules/ghostty
  ];
  home.packages = with pkgs; [
    swiftlint
    raycast
    jdk
    wezterm
    sioyek
    # spotify
    # discord
    # harper
    # emacs
  ];

  programs.zathura = {
    enable = false;
  };

  # services.ollama = {
  #   enable = true;
  #   package = pkgs-unstable.ollama;
  # };
}
