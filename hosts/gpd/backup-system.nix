{
  pkgs,
  inputs,
  ...
}: {
  imports = [
    ./hardware-configuration.nix
    ./dosuspend.nix
  ];

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.kernelPackages = pkgs.linuxPackages_latest;

  boot.binfmt = {
    emulatedSystems = ["aarch64-linux"];
    preferStaticEmulators = true;
  };

  networking = {
    hostName = "gpd";
    networkmanager.enable = false;
    useNetworkd = true;
  };

  time.timeZone = "Asia/Hong_Kong";

  nixpkgs.config.rocmSupport = true;

  services.xserver.enable = true;
  services.displayManager.gdm.enable = true;
  services.desktopManager.gnome.enable = true;

  services.flatpak.enable = true;
  services.spice-vdagentd.enable = true;
  services.blueman.enable = true;

  xdg.portal.wlr.enable = true;

  environment = {
    variables = {
      EDITOR = "nvim";
    };
  };

  environment.sessionVariables.NIXOS_OZONE_WL = "1";
  environment.sessionVariables.COSMIC_DATA_CONTROL_ENABLED = 1;
  systemd.packages = pkgs.lib.optional (pkgs ? observatory) pkgs.observatory;
  systemd.services.monitord.wantedBy = ["multi-user.target"];

  services.printing.enable = true;

  services.pipewire = {
    enable = true;
    pulse.enable = true;
  };

  environment.systemPackages = with pkgs; [
    vim
    wget
    firefox
    google-chrome
    neovim
    git
    gcc
    wqy_microhei
    ntfs3g
    qemu
    starship
    zsh
    duf
    gnumake
    flex
    bison
    elfutils
    libelf
    pkg-config
    clapper
    bat
    just

    adwaita-icon-theme
    radeontop
    corectrl
    ddns-go
    btop-rocm
  ];

  programs = {
    gamescope = {
      enable = true;
      capSysNice = true;
    };
    steam = {
      enable = true;
      gamescopeSession.enable = true;
      remotePlay.openFirewall = true;
      dedicatedServer.openFirewall = true;
      localNetworkGameTransfers.openFirewall = true;
    };
    zsh.enable = true;
  };

  services.openssh.enable = true;

  system.stateVersion = "25.11";
}
