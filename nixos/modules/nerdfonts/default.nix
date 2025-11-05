{pkgs, ...}: {
  fonts.packages = with pkgs; [
    noto-fonts
    noto-fonts-cjk-sans
    noto-fonts-emoji
    liberation_ttf
    nerd-fonts.fira-code
    nerd-fonts.droid-sans-mono
    mplus-outline-fonts.githubRelease
    dina-font
    proggyfonts
  ];
}
