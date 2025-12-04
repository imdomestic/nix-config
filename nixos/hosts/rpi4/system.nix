# Edit this configuration file to define what should be installed on
# your system. Help is available in the configuration.nix(5) man page, on
# https://search.nixos.org/options and in the NixOS manual (`nixos-help`).
{
  config,
  lib,
  pkgs,
  ...
}: {
  imports = [
    # Include the results of the hardware scan.
    ./hardware-configuration.nix
    # ../../modules/mihomo
    ../../modules/tuigreet
    ../../modules/keyd
  ];

  # Use the extlinux boot loader. (NixOS wants to enable GRUB by default)
  boot.loader.grub.enable = false;
  # Enables the generation of /boot/extlinux/extlinux.conf
  boot.loader.generic-extlinux-compatible.enable = true;
  boot.kernelPackages = pkgs.linuxPackages_latest;

  networking.hostName = "rpi4"; # Define your hostname.
  networking.networkmanager.enable = true; # Easiest to use and most distros use this by default.

  # Set your time zone.
  time.timeZone = "Asia/Shanghai";

  networking.proxy.default = "http://192.168.1.25:7890";
  networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";


  i18n.defaultLocale = "en_US.UTF-8";

  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users.hank = {
    isNormalUser = true;
    extraGroups = ["wheel"]; # Enable ‘sudo’ for the user.
    packages = with pkgs; [
      tree
    ];
  };

  security.sudo.wheelNeedsPassword = false;

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    vim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
    neovim
    wget
  ];

  programs.zsh.enable = true;

  services.pipewire.enable = true;

  services.openssh.enable = true;
  systemd.services.ddns-go = {
    enable = false;
    description = "Simple and easy to use DDNS. Automatically update domain name resolution to public IP (Support Aliyun, Tencent Cloud, Dnspod, Cloudflare, Callback, Huawei Cloud, Baidu Cloud, Porkbun, GoDaddy...)";

    wants = ["network.target"];
    after = ["network-online.target"];

    serviceConfig = {
      StartLimitInterval = 5;
      StartLimitBurst = 10;
      ExecStart = "${pkgs.ddns-go.outPath}/bin/ddns-go \"-l\" \":9876\" \"-f\" \"300\" \"-cacheTimes\" \"5\" \"-c\" \"/home/nix/.ddns_go_config.yaml\"";
      Restart = "always";
      RestartSec = 120;
      EnvironmentFile = "-/etc/sysconfig/ddns-go";
    };

    wantedBy = ["multi-user.target"];
  };

  networking.firewall.enable = false;
  system.stateVersion = "25.05"; # Did you read the comment?
}
