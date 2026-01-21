# Edit this configuration file to define what should be installed on
# your system. Help is available in the configuration.nix(5) man page, on
# https://search.nixos.org/options and in the NixOS manual (`nixos-help`).
{
  inputs,
  pkgs,
  ...
}: {
  imports = [
    ./hardware-configuration.nix
    ../../modules/dae
    ../../modules/keyd
    ../../modules/tuigreet
  ];

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  boot.supportedFilesystems = ["bcachefs"];
  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.binfmt.emulatedSystems = ["aarch64-linux"];

  # rdma
  # boot.kernelModules = [
  #   "ib_core" # RDMA 核心
  #   "ib_uverbs" # 用户态接口
  #   "rdma_ucm" # 用户空间连接管理
  #   "mlx4_ib" # Mellanox CX3 的 RDMA 驱动 (关键！)
  #   "rpcrdma" # NFS 客户端 RDMA 模块
  #   "svcrdma" # NFS 服务端 RDMA 模块
  # ];
  #
  # systemd.mounts = [
  #   {
  #     type = "nfs";
  #     what = "192.168.1.11:/data/rdma"; # E5 的万兆直连 IP
  #     where = "/data/rdma";
  #
  #     # 核心参数：
  #     # proto=rdma: 强制使用 RDMA 传输
  #     # port=20049: 指定服务端监听的 RDMA 端口
  #     options = "proto=tcp,vers=4.2,soft,intr";
  #
  #     # 依赖网络上线后再挂载
  #     wants = ["network-online.target"];
  #     after = ["network-online.target"];
  #   }
  # ];
  #
  # systemd.automounts = [
  #   {
  #     where = "/data/rdma";
  #     wantedBy = ["multi-user.target"];
  #   }
  # ];

  networking = {
    hostName = "x470";
    networkmanager.enable = false;
    useDHCP = false;
    useNetworkd = true;
    nftables.enable = true;
    firewall = {
      enable = false;
      trustedInterfaces = ["enp34s0" "enp40s0" " enp40s0d1" "br-lan"];
      checkReversePath = false;
    };
    wg-quick.interfaces = {
      wg0 = {
        configFile = "${inputs.wg-config.outPath}/client_00076.conf";
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
      matchConfig.Name = "enp40s0";
      networkConfig.Bridge = "br-lan";
      linkConfig.RequiredForOnline = "enslaved";
    };

    networks."20-lan2-uplink" = {
      matchConfig.Name = "enp34s0";
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
    #   matchConfig.Name = "enp40s0d1";
    #   networkConfig = {
    #     Address = "192.168.254.2/30";
    #   };
    #   linkConfig = {
    #     MTUBytes = 9000;
    #     RequiredForOnline = "no";
    #   };
    # };
  };

  # Set your time zone.
  time.timeZone = "Hongkong";
  services.xserver.enable = true;
  services.xserver.videoDrivers = ["nvidia"];
  hardware.nvidia = {
    modesetting.enable = true;
    open = false;
    nvidiaSettings = true;
  };
  hardware.nvidia-container-toolkit.enable = true;
  environment.sessionVariables = {
    LIBVA_DRIVER_NAME = "nvidia";
    GBM_BACKEND = "nvidia-drm";
    __GLX_VENDOR_LIBRARY_NAME = "nvidia";
  };

  # Enable the GNOME Desktop Environment.
  services.displayManager.gdm.enable = false;
  services.desktopManager.gnome.enable = true;
  users.users.hank = {
    isNormalUser = true;
    extraGroups = ["wheel"]; # Enable ‘sudo’ for the user.
    packages = with pkgs; [
      tree
    ];
  };
  programs = {
    zsh.enable = true;
    chromium.enable = true;
    firefox.enable = true;
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

  hardware = {
    graphics = {
      enable = true;
      enable32Bit = true;
    };
    xone.enable = true;
  };

  nixpkgs.config = {
    cudaSupport = true;
    cudaCababilities = ["6.1"];
  };

  environment.systemPackages = with pkgs; [
    rdma-core

    cachix
    virt-manager
    virt-viewer
    spice
    spice-gtk
    spice-protocol
    virtio-win
    win-spice
    ddns-go
    btop-cuda

    steam-run
    steamcmd

    inputs.zen-browser.packages."${system}".default
  ];

  services.iperf3.enable = true;
  services.openssh.enable = true;
  services.tailscale.enable = true;

  services.ollama = {
    enable = true;
    acceleration = "cuda";
    host = "0.0.0.0";
  };

  systemd.settings.Manager.RebootWatchdogSec = 60;
  systemd.settings.Manager.RuntimeWatchdogSec = 60;

  system.stateVersion = "26.05";
}
