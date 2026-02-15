{
  pkgs,
  pkgs-unstable,
  inputs,
  ...
}: {
  imports = [
    # ../../modules/hyprland
    ../../modules/walker
    ../../modules/tofi
    inputs.walker.homeManagerModules.default
    inputs.catppuccin.homeModules.catppuccin
    inputs.noctalia.homeModules.default
    inputs.niri.homeModules.niri
    ../../modules/kitty
    ../../modules/ghostty
    ../../modules/gui
    ../../modules/noctalia
  ];
  # ++ pkgs.lib.optional (hostname == "b660") [../../modules/gui];

  programs.fuzzel.enable = true;

  # use qemu system session
  # dconf.settings = {
  #   "org/virt-manager/virt-manager/connections" = {
  #     autoconnect = ["qemu:///system"];
  #     uris = ["qemu:///system"];
  #   };
  # };

  home.sessionVariables.NIXOS_OZONE_WL = "1";

  home.packages = with pkgs; [
    iotop
    iftop
    strace
    ltrace
    lsof
    pstree

    sysstat
    lm_sensors
    ethtool
    pciutils # lspci
    usbutils # lsusb

    edid-decode
    dmidecode

    # apps
    prismlauncher
    zathura
    nwg-look
    pavucontrol
    grimblast
    wl-clipboard
    playerctl
    google-chrome
    spotify
    qq
    wechat-uos
    cider
    sioyek
    upscayl
    sioyek
  ];

  # catppuccin.gtk = {
  #   enable = true;
  #   accent = "lavender";
  #   icon.enable = true;
  #   icon.accent = "lavender";
  # };
  # catppuccin.yazi.enable = true;
  # catppuccin.zellij.enable = true;
  # catppuccin.btop.enable = true;
}
