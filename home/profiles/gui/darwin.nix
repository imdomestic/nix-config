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
    jdk
    wezterm
    # spotatui
    sioyek
    pkgs-unstable.raycast
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
