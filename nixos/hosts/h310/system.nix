{pkgs, ...}: {
  boot = {
    loader = {
      systemd-boot = {
        enable = true;
        xbootldrMountPoint = "/boot";
      };
      efi = {
        canTouchEfiVariables = true;
        efiSysMountPoint = "/efi";
      };
    };
    supportedFilesystems = ["bcachefs"];
    kernelPackages = pkgs.linuxPackages_latest;
  };

  networking = {
    networkmanager.enable = false;
    useNetworkd = true;
  };

  systemd.network.networks."10-wired" = {
    matchConfig.Name = "en*";
    networkConfig.DHCP = "yes";
  };

  time.timeZone = "Asia/Shanghai";
  i18n.defaultLocale = "en_US.UTF-8";

  # The shared users module assigns zsh as every account's login shell.
  programs.zsh.enable = true;

  # bcachefs does not support swapfiles. Give this 8 GiB machine some
  # compressed swap without adding another disk partition.
  zramSwap.enable = true;

  system.stateVersion = "26.05";
}
