{pkgs, ...}: {
  imports = [
    ../../modules/vicinae
    ../../modules/ghostty
    ../../modules/gui
  ];
  # ++ pkgs.lib.optional (hostname == "b660") [../../modules/gui];

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
    sioyek
    upscayl
    sioyek
  ];
}
