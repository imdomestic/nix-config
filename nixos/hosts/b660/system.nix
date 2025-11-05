{
  pkgs,
  inputs,
  ...
}: {
  imports = [
    ./hardware-configuration.nix
    ../../modules/mihomo
    ../../modules/grub
    ../../modules/tuigreet
    ../../modules/keyd
    ../../modules/man
    ../../modules/vfio
  ];

  boot.binfmt = {
    emulatedSystems = ["aarch64-linux"];
    preferStaticEmulators = true;
  };

  # boot.extraModprobeConfig = ''
  #   options kvm_intel nested=1
  #   options kvm_intel emulate_invalid_guest_state=0
  #   options kvm ignore_msrs=1
  # '';

  networking.hostName = "b660"; # Define your hostname.
  networking.networkmanager.enable = true; # Easiest to use and most distros use this by default.

  # Set your time zone.
  time.timeZone = "Hongkong";

  # Configure network proxy if necessary
  networking.proxy.default = "http://127.0.0.1:7890";
  networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

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

  # Enable the X11 windowing system.
  services.xserver.enable = true;

  # Enable the GNOME Desktop Environment.
  services.xserver.displayManager.gdm.enable = false;
  services.desktopManager.gnome.enable = false;

  services.desktopManager.cosmic.enable = true;
  services.flatpak.enable = true;

  programs.zsh = {
    enable = true;
  };

  xdg.portal.wlr.enable = true;
  programs = {
    hyprland = {
      enable = true;
      withUWSM = true;
    };
    # waybar.enable = true;
    hyprlock.enable = true;
    # thunar.enable = true;
    virt-manager.enable = true;
    xwayland.enable = true;
  };

  services.spice-vdagentd.enable = true;
  services.blueman.enable = true;

  services.cockpit = {
    enable = true;
    openFirewall = true;
    port = 9091;
  };

  services.ollama = {
    enable = true;
    acceleration = "rocm";
    rocmOverrideGfx = "11.0.0";
    host = "0.0.0.0";
  };

  # services.llama-cpp = {
  #   enable = true;
  # };

  hardware.graphics = {
    enable = true;
    extraPackages = with pkgs; [
      rocmPackages.clr.icd
    ];
  };

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

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    vim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
    wget
    neovim
    git
    gcc
    wqy_microhei
    ntfs3g
    qemu
    starship
    zsh
    brightnessctl
    waybar
    nwg-dock-hyprland
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
    mihomo
    hmcl

    adwaita-icon-theme
    radeontop
    corectrl
    # daed
    ddns-go
    btop-rocm

    inputs.zen-browser.packages."${system}".default
    google-chrome

    # pkgsCross.riscv64.gcc14
  ];

  programs = {
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
  };
  hardware.xone.enable = true;

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # List services that you want to enable:

  # Enable the OpenSSH daemon.
  services.openssh.enable = true;

  networking.firewall.enable = false;

  networking.useDHCP = false;
  # networking.interfaces.enp6s0.useDHCP = true;
  networking.interfaces.br0.useDHCP = true;
  networking.bridges = {
    "br0" = {
      interfaces = ["eno1"];
    };
  };
  # Copy the NixOS configuration file and link it from the resulting system
  # (/run/current-system/configuration.nix). This is useful in case you
  # accidentally delete configuration.nix.
  # system.copySystemConfiguration = true;
  system.stateVersion = "24.11"; # Did you read the comment?
}
