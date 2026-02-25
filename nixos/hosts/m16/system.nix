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
    hostName = "m16"; # Define your hostname.
    networkmanager.enable = false;
    wireless.iwd.enable = true;

    useDHCP = false;
    useNetworkd = true;
    nameservers = ["1.1.1.1" "8.8.8.8"];
  };

  #   wg-quick.interfaces = {
  #     wg0 = {
  #       configFile = "${inputs.wg-config.outPath}/client_00024.conf";
  #       autostart = true;
  #     };
  #   };
  # };

  # Configure network proxy if necessary
  # networking.proxy.default = "http://127.0.0.1:7890";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  systemd.network = {
    wait-online.enable = false;
    enable = true;
    networks."wlan" = {
      matchConfig.Name = "wlan0";
      networkConfig = {
        DHCP = "yes";
      };
    };
  };

  #
  #   networks."20-lan-uplink" = {
  #     matchConfig.Name = "eno1";
  #     networkConfig.Bridge = "br-lan";
  #     linkConfig.RequiredForOnline = "enslaved";
  #   };
  #
  #   networks."30-br-lan" = {
  #     matchConfig.Name = "br-lan";
  #     networkConfig = {
  #       DHCP = "yes";
  #       IPv6AcceptRA = true;
  #     };
  #     linkConfig = {
  #       RequiredForOnline = "routable";
  #     };
  #   };
  # };

  time.timeZone = "Hongkong";

  nixpkgs.config.rocmSupport = true;

  services.xserver.enable = true;
  services.displayManager.gdm.enable = true;
  services.desktopManager.gnome.enable = true;

  services.flatpak.enable = true;
  services.spice-vdagentd.enable = true;
  services.blueman.enable = true;

  services.resolved.enable = true;

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

  # Enable sound.
  services.pipewire = {
    enable = true;
    pulse.enable = true;
  };

  users.users.linwhite = {
    isNormalUser = true;
    extraGroups = ["wheel"]; # Enable ‘sudo’ for the user.
    packages = with pkgs; [
      tree
    ];
  };

  environment.systemPackages = with pkgs; [
    vim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
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

    inputs.zen-browser.packages."${system}".default
    inputs.noctalia.packages.${system}.default
  ];

  programs = {
    niri = {
      package = pkgs.niri;
      enable = true;
    };
    gamescope = {
      enable = true;
      capSysNice = true;
    };
    steam = {
      enable = true;
      gamescopeSession.enable = true;
      remotePlay.openFirewall = true; # Open ports in the firewall for Steam Remote Play
      dedicatedServer.openFirewall = true; # Open ports in the firewall for Source Dedicated Server
      localNetworkGameTransfers.openFirewall = true; # Open ports in the firewall for Steam Local Network Game Transfers
    };
    zsh.enable = true;
  };

  services.openssh.enable = true;

  system.stateVersion = "25.11"; # Did you read the comment?
}
