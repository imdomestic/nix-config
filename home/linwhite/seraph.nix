# linwhite 在 seraph 上的东西:看机器状态的命令行工具。
{pkgs, ...}: {
  imports = [./modules/opencode/local-bonsai.nix];

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
