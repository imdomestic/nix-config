{
  config,
  pkgs,
  pkgs-unstable,
  lib,
  inputs,
  ...
}: let
  ddnsConfig = pkgs.writeText "ddns-go-config.yaml" ''
    dnsconf:
        - name: "sanuki"
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
            secret: smQyUYNVLeoAAAQ-REg7TViTxAU_lkkzwnSNBlpP
          ttl: ""
        - name: "imdomestic"
          ipv4:
            enable: false
            gettype: url
            url: https://myip.ipip.net, https://ddns.oray.com/checkip, https://ip.3322.net, https://4.ipw.cn, https://v4.yinghualuo.cn/bejson
            netinterface: wan0
            cmd: ""
            domains:
                - ""
          ipv6:
            enable: true
            gettype: netInterface
            url: https://speed.neu6.edu.cn/getIP.php, https://v6.ident.me, https://6.ipw.cn, https://v6.yinghualuo.cn/bejson
            netinterface: br-lan
            cmd: ""
            ipv6reg: ""
            domains:
                - tank:imdomestic.com
          dns:
            name: cloudflare
            id: ""
            secret: WY4F4gK8O-VgV1P7dGnic4yNSxmtPBep5OXuh2Js
          ttl: ""
    user:
        username: genisys
        password: $2a$10$TsaVL35GpATzwiW8fefl4uL78HbZ3Ukj4ThdwaFSW26DTIuwZoPdW
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
    # ../../modules/mihomo
    ../../modules/grub
    ../../modules/tuigreet
    ../../modules/keyd
    ../../modules/minecraft/wuxi.nix
  ];

  boot.initrd.kernelModules = [
    "dm-snapshot" # when you are using snapshots
    "dm-raid" # e.g. when you are configuring raid1 via: `lvconvert -m1 /dev/pool/home`
    "dm-cache-default" # when using volumes set up with lvmcache
  ];
  boot.supportedFilesystems = ["xfs" "bcachefs"];
  boot.kernelPackages = pkgs.linuxPackages_6_18;
  boot.binfmt.emulatedSystems = ["aarch64-linux"];
  swapDevices = [
    {
      device = "/var/lib/swapfile";
      size = 16 * 1024;
    }
  ];

  fileSystems."/data" = {
    device = "UUID=2dc8bfeb-1f02-4c70-94dc-ecd07593e7f1";
    fsType = "bcachefs";
    options = ["defaults" "nofail" "compression=zstd" "noatime"];
  };

  # rdma
  # boot.kernelModules = [
  #   "ib_core" # RDMA 核心
  #   "ib_uverbs" # 用户态接口
  #   "rdma_ucm" # 用户空间连接管理
  #   "mlx4_ib" # Mellanox CX3 的 RDMA 驱动 (关键！)
  #   "rpcrdma" # NFS 客户端 RDMA 模块
  #   "svcrdma" # NFS 服务端 RDMA 模块
  # ];

  systemd = {
    tmpfiles.rules = [
      "d     /data/builds     0777 root  root  -"
      "d     /data/rdma       0777 root  root  -"
      "d     /data/srv        0777 root  root  -"
      "d     /data/lib/ollama 0777 root  root  -"
      "d     /data/services   0755 root  root  -"
      "d     /data/nas        0755 hank  users -"
      "d     /data/nas/public 0775 hank  users -"
      "d     /data/services/matrix-synapse 0700 matrix-synapse matrix-synapse -"
    ];
    services.nix-daemon.environment.TMPDIR = "/data/builds";
  };

  services.nfs.server = {
    exports = ''
      /data/rdma 192.168.1.7(rw,sync,no_subtree_check,no_root_squash,insecure)
    '';
  };

  services.tailscale.enable = true;

  services.filebrowser = {
    enable = true;
    user = "hank"; # FileBrowser 以 hank 身份运行
    group = "users";
    openFirewall = true;
    settings = {
      address = "0.0.0.0";
      port = 8080;
      root = "/data/nas";
      database = "/var/lib/filebrowser/filebrowser.db";
      log = "/var/log/filebrowser.log";
    };
  };

  services.samba = {
    enable = true;
    openFirewall = true;

    settings = {
      global = {
        "workgroup" = "WORKGROUP";
        "server string" = "NixOS NAS";
        "netbios name" = "nixos-nas";
        "security" = "user";
        "min protocol" = "SMB2_10";

        "fruit:metadata" = "stream";
        "fruit:model" = "MacSamba";
        "fruit:posix_rename" = "yes";
        "fruit:veto_appledouble" = "no";
        "fruit:nfs_aces" = "no";
        "fruit:wipe_intentionally_left_blank_rfork" = "yes";
        "fruit:delete_empty_adfiles" = "yes";
      };

      public = {
        "path" = "/data/nas/public";
        "browseable" = "yes";
        "read only" = "no";
        "guest ok" = "yes";
        "create mask" = "0664";
        "directory mask" = "0775";
        "force user" = "hank";
        "force group" = "users";
      };

      home_hank = {
        "path" = "/data/nas";
        "browseable" = "yes";
        "read only" = "no";
        "guest ok" = "no";
        "valid users" = "hank";
        "create mask" = "0644";
        "directory mask" = "0755";
        "force user" = "hank";
        "force group" = "users";
      };
    };
  };

  services.samba-wsdd = {
    enable = true;
    openFirewall = true;
  };

  services.nginx = {
    enable = true;

    recommendedGzipSettings = true;
    recommendedOptimisation = true;
    recommendedProxySettings = true;

    clientMaxBodySize = "0"; # 0 代表不限制大小

    virtualHosts."tank.local" = {
      default = true;
      listen = [
        {
          addr = "0.0.0.0";
          port = 80;
        }
      ];

      # --- 公共目录 (对应原来的 public) ---
      locations."/public/" = {
        alias = "/data/nas/public/"; # 注意末尾的斜杠

        # 开启 WebDAV 方法
        extraConfig = ''
          dav_methods PUT DELETE MKCOL COPY MOVE;
          dav_ext_methods PROPFIND OPTIONS;
          dav_access user:rw group:rw all:r;

          # 允许列出目录文件
          autoindex on;

          # 解决 macOS Finder 甚至 Windows 的一些兼容性问题
          create_full_put_path on;
        '';
      };

      # --- 个人目录 (对应原来的 home_hank) ---
      locations."/hank/" = {
        alias = "/data/nas/"; # 这里映射整个 /data/nas

        extraConfig = ''
          dav_methods PUT DELETE MKCOL COPY MOVE;
          dav_ext_methods PROPFIND OPTIONS;
          dav_access user:rw group:rw all:rw;

          autoindex on;
          create_full_put_path on;
        '';

        basicAuthFile = "/etc/nixos/webdav.htpasswd"; # 密码文件路径，见下文
      };
    };
  };

  networking = {
    hostName = "tank"; # Define your hostname.
    networkmanager.enable = false; # Easiest to use and most distros use this by default.
    useDHCP = false;
    useNetworkd = true;
    nftables.enable = true;
    firewall = {
      enable = false;
      trustedInterfaces = ["enp5s0" "ens6" "br-lan"];
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

    networks."20-lan1-uplink" = {
      matchConfig.Name = "enp5s0";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    networks."20-lan2-uplink" = {
      matchConfig.Name = "ens6";
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

    # networks."30-10g-backend" = {
    #   matchConfig.Name = "ens6d1";
    #   networkConfig = {
    #     Address = "192.168.254.1/30";
    #   };
    #   linkConfig = {
    #     RequiredForOnline = "no";
    #   };
    # };
  };

  # Set your time zone.
  time.timeZone = "Hongkong";

  # Enable the X11 windowing system.
  services.xserver.enable = true;
  services.xserver.videoDrivers = ["nvidia"];
  # nixpkgs.config.cudaSupport = true;
  hardware.graphics.enable = true;
  hardware.nvidia = {
    modesetting.enable = true;
    open = true;
    nvidiaSettings = true;
  };
  hardware.nvidia-container-toolkit.enable = true;
  environment.sessionVariables = {
    LIBVA_DRIVER_NAME = "nvidia";
    GBM_BACKEND = "nvidia-drm";
    __GLX_VENDOR_LIBRARY_NAME = "nvidia";
  };

  # Enable the GNOME Desktop Environment.
  services.displayManager.gdm.enable = true;
  services.desktopManager.gnome.enable = true;

  services.sunshine = {
    enable = true;
    autoStart = true;
    capSysAdmin = true;
    openFirewall = true;
  };

  xdg.portal.enable = true;

  services.gnome.gnome-remote-desktop.enable = true;
  services.xrdp = {
    enable = true;
    openFirewall = true;
    defaultWindowManager = "${pkgs.gnome-session}/bin/gnome-session";
  };

  services.displayManager.autoLogin.enable = false;
  services.getty.autologinUser = null;

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

  # for cs2 dedicated server and cmi
  services.mysql = {
    package = pkgs.mariadb;
    enable = true;
    ensureDatabases = ["cs2" "minecraft"];
    ensureUsers = [
      {
        name = "cs2";
        ensurePermissions = {
          "*.*" = "ALL PRIVILEGES";
        };
      }
      {
        name = "mc_user";
        ensurePermissions = {
          "*.*" = "ALL PRIVILEGES";
        };
      }
    ];
    settings = {
      mysqld = {
        bind-address = "0.0.0.0";
      };
    };
  };

  services.postgresql = {
    enable = true;
    dataDir = "/data/lib/postgresql/${config.services.postgresql.package.psqlSchema}";
    ensureDatabases = ["luckperms" "minecraft" "matrix-synapse"];
    enableTCPIP = true;
    ensureUsers = [
      {
        name = "minecraft";
        ensureDBOwnership = true;
      }
      {
        name = "matrix-synapse";
        ensureDBOwnership = true;
      }
    ];
    authentication = pkgs.lib.mkForce ''
      # TYPE  DATABASE        USER            ADDRESS                 METHOD
      local   all             all                                     trust
      host    luckperms       minecraft       127.0.0.1/32            trust
      host    luckperms       minecraft       10.0.0.0/24             md5
      host    luckperms       minecraft       10.42.0.0/24            md5
    '';
  };

  services.matrix-synapse = {
    enable = true;
    dataDir = "/data/services/matrix-synapse";
    settings = {
      server_name = "sh.imdomestic.com";
      public_baseurl = "https://sh.imdomestic.com:8448";
      sliding_sync.enabled = true;
      turn_uris = ["turn:sh.imdomestic.com:3478?transport=udp" "turn:sh.imdomestic.com:3478?transport=tcp"];
      turn_shared_secret = "your_turn_shared_secret_here";
      turn_user_lifetime = "1h";

      listeners = [
        {
          port = 8008;
          bind_addresses = ["0.0.0.0"];
          type = "http";
          tls = false; # NAS 本地不搞 SSL，让 VPS 处理
          x_forwarded = true;
          resources = [
            {
              names = ["client" "federation"];
              compress = false;
            }
          ];
        }
      ];

      database = {
        name = "psycopg2";
        args = {
          user = "matrix-synapse";
          database = "matrix-synapse";
          host = "/run/postgresql";
        };
        allow_unsafe_locale = true;
      };

      enable_registration = false;
      registration_shared_secret = "hbhbhb";
      max_upload_size = "50M";
    };
  };

  services.coturn = {
    enable = true;
    no-cli = true;
    realm = "sh.imdomestic.com";
    static-auth-secret = "your_turn_shared_secret_here";

    listening-port = 3478;
    tls-listening-port = 5349;
    relay-ips = ["127.0.0.1"];

    extraConfig = ''
      external-ip=101.132.183.117

      allow-loopback-peers
      min-port=49152
      max-port=65535
    '';
  };

  services.murmur = {
    enable = true;
    registerName = "imdomestic";
    password = "hbhbhb";
    port = 64738;
    bandwidth = 128000;
  };

  services.k3s = {
    enable = false;
    role = "server";
    token = "hbhbhb";
    clusterInit = true;
    extraFlags = [
      "--node-ip=10.0.0.66"
      "--node-external-ip=10.0.0.66"
      "--bind-address=10.0.0.66"
      "--advertise-address=10.0.0.66"
      "--flannel-iface=wg0"
      "--disable traefik"
    ];
    manifests = {
      "00-argocd-ns".content = {
        apiVersion = "v1";
        kind = "Namespace";
        metadata.name = "argocd";
      };
    };
  };

  systemd.nspawn."debian-guest" = {
    enable = true;
    execConfig = {
      Boot = true;
    };
    networkConfig = {
      Bridge = "br-lan";
    };
  };

  systemd.services."systemd-nspawn@debian-guest" = {
    enable = true;
    wantedBy = ["machines.target"];
    overrideStrategy = "asDropin";
  };

  programs.zsh = {
    enable = true;
  };

  programs.nix-index-database.comma.enable = true;
  programs.nix-index = {
    enableBashIntegration = false;
    enableFishIntegration = false;
    enableZshIntegration = false;
  };
  programs.command-not-found.enable = false;

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

  services.ollama = {
    package = pkgs-unstable.ollama;
    enable = true;
    # acceleration = "cuda";
    acceleration = false;
    host = "0.0.0.0";
    home = "/data/lib/ollama";
    environmentVariables = {
      OLLAMA_KEEP_ALIVE = "-1";
    };
    loadModels = [
      "qwen3:8b"
    ];
    syncModels = true;
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

  environment.systemPackages = with pkgs; [
    rdma-core
    matrix-synapse
    # infiniband-diags
    # libibverbs

    debootstrap
    cachix
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
    btop-cuda
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

    steam-run
    steamcmd
  ];

  programs.steam = {
    enable = true;
    remotePlay.openFirewall = true; # Open ports in the firewall for Steam Remote Play
    dedicatedServer.openFirewall = true; # Open ports in the firewall for Source Dedicated Server
  };

  services.openssh.enable = true;
  services.vscode-server.enable = true;

  services.iperf3.enable = true;

  systemd.services.ddns-go = {
    enable = true;
    description = "ddns";

    wantedBy = ["multi-user.target"];
    wants = ["network-online.target"];
    after = ["network-online.target"];

    serviceConfig = {
      ExecStart = "${pkgs.ddns-go.outPath}/bin/ddns-go -f 300 -c ${ddnsConfig}";
      Restart = "always";
      RestartSec = 5;
    };
  };

  systemd.settings.Manager.RebootWatchdogSec = 60;
  systemd.settings.Manager.RuntimeWatchdogSec = 60;

  system.stateVersion = "24.11"; # Did you read the comment?
}
