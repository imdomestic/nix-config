{
  pkgs,
  inputs,
  ...
}: {
  imports = [
    ./hardware-configuration.nix
    # ../../modules/mihomo
    # ../../modules/grub
    # ../../modules/tuigreet
    ../../modules/keyd
    ../../modules/man
    ../../modules/vfio
  ];

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.loader.systemd-boot.xbootldrMountPoint = "/boot";
  boot.loader.efi.efiSysMountPoint = "/efi";
  boot.kernelPackages = pkgs.linuxPackages_latest;

  boot.binfmt = {
    emulatedSystems = ["aarch64-linux"];
    preferStaticEmulators = true;
  };

  # boot.extraModprobeConfig = ''
  #   options kvm_intel nested=1
  #   options kvm_intel emulate_invalid_guest_state=0
  #   options kvm ignore_msrs=1
  # '';

  networking = {
    hostName = "b650"; # Define your hostname.
    networkmanager.enable = false; # Easiest to use and most distros use this by default.
    useDHCP = false;
    useNetworkd = true;
    nftables.enable = true;
    firewall = {
      enable = false;
      trustedInterfaces = ["eno1" "br-lan"];
      checkReversePath = false;
    };
    wg-quick.interfaces = {
      wg0 = {
        configFile = "${inputs.wg-config.outPath}/client_00067.conf";
        autostart = true;
      };
    };
  };
  # Configure network proxy if necessary
  # networking.proxy.default = "http://127.0.0.1:7890";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  systemd.network = {
    enable = true;
    netdevs."10-br-lan" = {
      netdevConfig = {
        Kind = "bridge";
        Name = "br-lan";
      };
    };

    networks."20-lan-uplink" = {
      matchConfig.Name = "eno1";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    networks."30-br-lan" = {
      matchConfig.Name = "br-lan";
      networkConfig = {
        DHCP = "yes";
        IPv6AcceptRA = true;
      };
      linkConfig = {
        RequiredForOnline = "routable";
      };
    };
  };

  time.timeZone = "Hongkong";

  nixpkgs.config.rocmSupport = true;

  security.pam.loginLimits = [
    {
      domain = "@kvm";
      type = "soft";
      item = "memlock";
      value = "unlimited";
    }
    {
      domain = "@kvm";
      type = "hard";
      item = "memlock";
      value = "unlimited";
    }
    {
      domain = "@libvirt";
      type = "soft";
      item = "memlock";
      value = "unlimited";
    }
    {
      domain = "@libvirt";
      type = "hard";
      item = "memlock";
      value = "unlimited";
    }
  ];

  services.udev.extraRules = ''
    SUBSYSTEM=="vfio", OWNER="root", GROUP="kvm"
  '';

  services.xserver.enable = true;
  services.displayManager.gdm.enable = true;
  services.desktopManager.gnome.enable = true;

  services.flatpak.enable = true;
  services.spice-vdagentd.enable = true;
  services.blueman.enable = true;

  xdg.portal.wlr.enable = true;

  # services.ollama = {
  #   enable = true;
  #   acceleration = "rocm";
  #   rocmOverrideGfx = "11.0.0";
  #   host = "0.0.0.0";
  # };

  # services.llama-cpp = {
  #   enable = true;
  # };

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

  system.stateVersion = "24.11"; # Did you read the comment?
}
