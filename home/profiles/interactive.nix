{pkgs, ...}: {
  home.packages = with pkgs; [
    bat
    fastfetch
    eza
    duf
    btop
  ];

  programs.yazi = {
    enable = true;
    shellWrapperName = "y";
    settings.theme.flavor = {
      dark = "kanso-ink";
      light = "kanso-pearl";
    };
    flavors = {
      kanso-ink = ../modules/yazi/kanso-ink.yazi;
      kanso-pearl = ../modules/yazi/kanso-pearl.yazi;
    };
  };

  programs.fzf = {
    enable = true;
    defaultOptions = ["--height 40%" "--layout=reverse" "--border"];
  };

  programs.zoxide = {
    enable = true;
    enableNushellIntegration = true;
  };
}
