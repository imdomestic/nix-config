{pkgs, ...}: {
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
    pciutils
    usbutils
    dmidecode
  ];
}
