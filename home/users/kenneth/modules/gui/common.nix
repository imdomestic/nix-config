{pkgs, ...}: {
  imports = [../ghostty];

  home.packages = with pkgs; [
    swiftlint
    jdk
    sioyek
  ];

  programs.zathura.enable = false;
}
