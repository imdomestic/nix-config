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
    ../../modules/fcitx5
    ../../modules/nerdfonts
    ../../modules/virtualisation
  ];

  boot.initrd.kernelModules = [
    "dm-snapshot" # when you are using snapshots
    "dm-raid" # e.g. when you are configuring raid1 via: `lvconvert -m1 /dev/pool/home`
    "dm-cache-default" # when using volumes set up with lvmcache
  ];
  boot.supportedFilesystems = ["xfs"];

  fileSystems."/mnt/storage" = {
    device = "/dev/vg1/lv_storage";
    fsType = "xfs";
    options = [
      "defaults"
      # "rw"
      # "group=wheel"
    ];
    # postMount = ''
    #   chown root:wheel /mnt/storage
    #   chmod 2775 /mnt/storage
    # '';
  };

  services.lvm.boot.thin.enable = true; # when using thin provisioning or caching
  services.lvm.enable = true;

  networking.hostName = "tank"; # Define your hostname.
  networking.networkmanager.enable = true; # Easiest to use and most distros use this by default.

  # Set your time zone.
  time.timeZone = "Hongkong";

  # Configure network proxy if necessary
  networking.proxy.default = "http://127.0.0.1:7890";
  networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  nixpkgs.config.rocmSupport = true;

  # Enable the X11 windowing system.
  services.xserver.enable = true;

  # Enable the GNOME Desktop Environment.
  services.displayManager.gdm.enable = true;
  services.desktopManager.gnome.enable = true;

  services.xrdp.enable = true;
  services.xrdp.defaultWindowManager = "xfce4-session";
  services.xrdp.openFirewall = true;

  # services.cockpit = {
  #   enable = true;
  #   openFirewall = true;
  #   settings = {
  #     WebService = {
  #       AllowUnencrypted = true;
  #     };
  #   };
  # };

  services.samba = {
    package = pkgs.samba4Full;
    enable = true;
    securityType = "user";
    openFirewall = true;
    settings.public = {
      path = "/mnt/storage/share";
      writable = "true";
      comment = "Hello World!";
      extraConfig = ''
        server smb encrypt = required
        server min protocol = SMB3_00
      '';
    };
  };

  services.jellyfin = {
    enable = true;
    openFirewall = true;
  };

  services.avahi = {
    publish.enable = true;
    publish.userServices = true;
    # ^^ Needed to allow samba to automatically register mDNS records (without the need for an `extraServiceFile`
    nssmdns4 = true;
    # ^^ Not one hundred percent sure if this is needed- if it aint broke, don't fix it
    enable = true;
    openFirewall = true;
  };

  services.samba-wsdd = {
    enable = true;
    openFirewall = true;
  };

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

  # services.ollama = {
  #   enable = true;
  #   acceleration = "rocm";
  #   rocmOverrideGfx = "10.3.0";
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
      LIBVIRT_DEFAULT_URI = "qemu:///system";
    };
  };

  environment.sessionVariables.NIXOS_OZONE_WL = "1";

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
    xfsprogs

    #virtualisation
    virt-manager
    virt-viewer
    spice
    spice-gtk
    spice-protocol
    win-virtio
    win-spice
    adwaita-icon-theme
    radeontop
    corectrl
    # daed
    ddns-go
    btop-rocm
    pkgs.jellyfin
    pkgs.jellyfin-web
    pkgs.jellyfin-ffmpeg

    inputs.zen-browser.packages."${system}".default

    # pkgsCross.riscv64.gcc14

    # make waybar happy
    (pkgs.python3.withPackages (python-pkgs:
      with python-pkgs; [
        # select Python packages here
        pandas
        requests
      ]))
  ];

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
  services.vscode-server.enable = true;
  # services.thymis-controller = {
  #   enable = true;
  #   system-binfmt-aarch64-enable = true; # enables emulation of aarch64 binaries, default is true on x86_64, needed for building aarch64 images on x86_64
  #   system-binfmt-x86_64-enable = false; # enables emulation of x86_64 binaries, default is false
  #   recommended-nix-gc-settings-enable = true; # enables recommended Nix garbage collection settings, default is true
  #   # repo-path = "/var/lib/thymis/repository"; # directory where the controller will store the repository holding the project
  #   # database-url = "sqlite:////var/lib/thymis/thymis.sqlite"; # URL of the database
  #   base-url = "https://my-thymis-controller/"; # base URL of the controller, how it will be accessed from the outside
  #   agent-access-url = "https://my-thymis-controller/"; # URL of the controller to be used by the agents
  #   auth-basic = true; # whether to enable authentication using a basic username/password
  #   auth-basic-username = "admin"; # username for basic authentication
  #   auth-basic-password-file = "/var/lib/thymis/auth-basic-password"; # file containing the password for basic authentication
  #   # content will be automatically generated if it does not exist
  #   listen-host = "0.0.0.0"; # host on which the controller listens for incoming connections
  #   listen-port = 8000; # port on which the controller listens for incoming connections
  #   nginx-vhost-enable = true; # whether to enable the Nginx virtual host
  #   nginx-vhost-name = "thymis"; # name of the Nginx virtual host
  # };
  # Configure the Nginx virtual host
  # services.nginx = {
  #   enable = true;
  #   virtualHosts."thymis" = {
  #     serverName = "my-thymis-controller";
  #     enableACME = false;
  #     forceSSL = false;
  #   };
  # };

  systemd.services.ddns-go = {
    enable = true;
    description = "Simple and easy to use DDNS. Automatically update domain name resolution to public IP (Support Aliyun, Tencent Cloud, Dnspod, Cloudflare, Callback, Huawei Cloud, Baidu Cloud, Porkbun, GoDaddy...)";

    wants = ["network.target"];
    after = ["network-online.target"];

    serviceConfig = {
      StartLimitInterval = 5;
      StartLimitBurst = 10;
      ExecStart = "${pkgs.ddns-go.outPath}/bin/ddns-go \"-l\" \":9876\" \"-f\" \"300\" \"-cacheTimes\" \"5\" \"-c\" \"/home/genisys/.ddns_go_config.yaml\"";
      Restart = "always";
      RestartSec = 120;
      EnvironmentFile = "-/etc/sysconfig/ddns-go";
    };

    wantedBy = ["multi-user.target"];
  };

  # Open ports in the firewall.
  # networking.firewall.allowedTCPPorts = [ ... ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # Or disable the firewall altogether.
  networking.firewall.enable = false;

  networking.useDHCP = false;
  # networking.interfaces.enp6s0.useDHCP = true;
  networking.interfaces.br0.useDHCP = true;
  networking.bridges = {
    "br0" = {
      interfaces = ["enp4s0"];
    };
  };
  systemd.enableEmergencyMode = false;

  system.stateVersion = "24.11"; # Did you read the comment?
}
