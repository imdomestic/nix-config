{
  pkgs,
  inputs,
  ...
}: let
  ddnsConfig = pkgs.writeText "ddns-go-config.yaml" ''
    dnsconf:
        - name: ""
          ipv4:
            enable: false
            gettype: url
            url: https://myip.ipip.net, https://ddns.oray.com/checkip, https://ip.3322.net, https://4.ipw.cn, https://v4.yinghualuo.cn/bejson
            netinterface: br0
            cmd: ""
            domains:
                - ""
          ipv6:
            enable: true
            gettype: netInterface
            url: https://speed.neu6.edu.cn/getIP.php, https://v6.ident.me, https://6.ipw.cn, https://v6.yinghualuo.cn/bejson
            netinterface: br-lan
            cmd: ""
            ipv6reg: '@2'
            domains:
                - tank.sanuki.cn
          dns:
            name: cloudflare
            id: ""
            secret: REMOVED_SECRET_CLOUDFLARE_API_TOKEN_44979882ce1a6a2c
          ttl: ""
    user:
        username: genisys
        password: REMOVED_SECRET_DDNS_BCRYPT_PASSWORD_HASH_fd4a24725221f5a3
    webhook:
        webhookurl: ""
        webhookrequestbody: ""
        webhookheaders: ""
    notallowwanaccess: false
    lang: zh
  '';
in {
  imports = [
    ./hardware-configuration.nix
    ../../modules/mihomo
    ../../modules/grub
    ../../modules/tuigreet
    ../../modules/keyd
  ];

  boot.initrd.kernelModules = [
    "dm-snapshot" # when you are using snapshots
    "dm-raid" # e.g. when you are configuring raid1 via: `lvconvert -m1 /dev/pool/home`
    "dm-cache-default" # when using volumes set up with lvmcache
  ];
  boot.supportedFilesystems = ["xfs" "bcachefs"];
  boot.kernelPackages = pkgs.linuxPackages_latest;

  # fileSystems."/mnt/storage" = {
  #   device = "/dev/vg1/lv_storage";
  #   fsType = "xfs";
  #   options = [
  #     "defaults"
  #     # "rw"
  #     # "group=wheel"
  #   ];
  #   # postMount = ''
  #   #   chown root:wheel /mnt/storage
  #   #   chmod 2775 /mnt/storage
  #   # '';
  # };

  services.lvm.boot.thin.enable = true; # when using thin provisioning or caching
  services.lvm.enable = true;

  networking = {
    hostName = "tank"; # Define your hostname.
    networkmanager.enable = false; # Easiest to use and most distros use this by default.
    useDHCP = false;
    useNetworkd = true;
    nftables.enable = true;
    firewall = {
      enable = false;
      trustedInterfaces = ["enp4s0" "br-lan"];
      checkReversePath = false;
    };
    wg-quick.interfaces = {
      wg0 = {
        configFile = "${inputs.wg-config.outPath}/client_00065.conf";
        autostart = true;
      };
    };
  };

  systemd.network = {
    enable = true;
    netdevs."10-br-lan" = {
      netdevConfig = {
        Kind = "bridge";
        Name = "br-lan";
      };
    };

    networks."20-lan-uplink" = {
      matchConfig.Name = "enp4s0";
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

  # services.samba = {
  #   package = pkgs.samba4Full;
  #   enable = true;
  #   securityType = "user";
  #   openFirewall = true;
  #   settings.public = {
  #     path = "/mnt/storage/share";
  #     writable = "true";
  #     comment = "Hello World!";
  #     extraConfig = ''
  #       server smb encrypt = required
  #       server min protocol = SMB3_00
  #     '';
  #   };
  # };

  # services.jellyfin = {
  #   enable = true;
  #   openFirewall = true;
  # };

  # services.avahi = {
  #   publish.enable = true;
  #   publish.userServices = true;
  #   # ^^ Needed to allow samba to automatically register mDNS records (without the need for an `extraServiceFile`
  #   nssmdns4 = true;
  #   # ^^ Not one hundred percent sure if this is needed- if it aint broke, don't fix it
  #   enable = true;
  #   openFirewall = true;
  # };

  # services.samba-wsdd = {
  #   enable = true;
  #   openFirewall = true;
  # };

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
    virtio-win
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

  services.openssh.enable = true;
  services.vscode-server.enable = true;

  systemd.services.ddns-go = {
    enable = true;
    description = "ddns";

    wants = ["network-online.target"];
    after = ["network-online.target"];

    serviceConfig = {
      ExecStart = "${pkgs.ddns-go.outPath}/bin/ddns-go -f 300 -c ${ddnsConfig}";
      Restart = "always";
      RestartSec = 5;
    };
  };

  systemd.enableEmergencyMode = false;
  systemd.watchdog.runtimeTime = "60s";
  systemd.watchdog.rebootTime = "60s";

  system.stateVersion = "24.11"; # Did you read the comment?
}
