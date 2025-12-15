{
  pkgs,
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

  # use qemu system session
  # dconf.settings = {
  #   "org/virt-manager/virt-manager/connections" = {
  #     autoconnect = ["qemu:///system"];
  #     uris = ["qemu:///system"];
  #   };
  # };

  home.sessionVariables.NIXOS_OZONE_WL = "1";

  home.packages = with pkgs; [
    # monitor
    iotop
    iftop
    strace
    ltrace
    lsof
    pstree

    # system tools
    sysstat
    lm_sensors
    ethtool
    pciutils # lspci
    usbutils # lsusb

    # sourcekit-lsp
    edid-decode
  ];

  # catppuccin.gtk = {
  #   enable = true;
  #   accent = "lavender";
  #   icon.enable = true;
  #   icon.accent = "lavender";
  # };
  catppuccin.yazi.enable = true;
  catppuccin.zellij.enable = true;
  catppuccin.btop.enable = true;
}
