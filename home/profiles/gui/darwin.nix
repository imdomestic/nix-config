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

  # services.ollama = {
  #   enable = true;
  #   package = pkgs-unstable.ollama;
  # };

  programs.direnv = {
    enable = true;
    nix-direnv.enable = true;
  };
}
