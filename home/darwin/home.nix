{pkgs, ...}: {
  imports = [
    ../../modules/kitty
    ../../modules/ghostty
  ];
  home.packages = with pkgs; [
    swiftlint
    raycast
    jdk
    wezterm
    spotify
    discord
    harper
    emacs
  ];

  programs.direnv = {
    enable = true;
    nix-direnv.enable = true;
  };

}
