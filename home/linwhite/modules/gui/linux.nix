{pkgs, ...}: {
  imports = [
    ../vicinae
    ../ghostty
  ];

  # use qemu system session
  # dconf.settings = {
  #   "org/virt-manager/virt-manager/connections" = {
  #     autoconnect = ["qemu:///system"];
  #     uris = ["qemu:///system"];
  #   };
  # };

  home.sessionVariables.NIXOS_OZONE_WL = "1";

  # 统一 Wayland / XWayland / GLFW / Qt 窗口的光标主题和尺寸，避免部分窗口光标意外放大
  gtk.enable = true;
  home.pointerCursor = {
    enable = true;
    gtk.enable = true;
    x11.enable = true;
    package = pkgs.adwaita-icon-theme;
    name = "Adwaita";
    size = 24;
  };

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

    # Desktop controls stay native; applications are in ../flatpak.nix.
    nwg-look
    pavucontrol
    grimblast
    wl-clipboard
    playerctl
  ];
}
