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
    (qq.overrideAttrs {
      version = "3.2.32-2026-08-12";
      src = fetchurl {
        url = "https://qqdl.gtimg.cn/qqfile/QQNT/9.9.33/release/3f89efc5/QQ_3.2.32_260812_${
          if stdenv.hostPlatform.isAarch64
          then "arm64"
          else "amd64"
        }_01.deb";
        hash =
          if stdenv.hostPlatform.isAarch64
          then "sha256-h5bM/WaswCXvGNs3GFUy1AvIxYkh4X2m0owpWsvPj5I="
          else "sha256-0IXdiTlyJQYeufGUMI9ogSmBjtRFd36XpKChbhPXsOg=";
      };
    })
    wechat-uos
    sioyek
    upscayl
    sioyek
  ];
}
