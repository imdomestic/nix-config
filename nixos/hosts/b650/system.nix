{
  pkgs,
  inputs,
  ...
}: let
  wg = import ../../../lib/wgClient.nix {inherit pkgs;} {
    conf = "${inputs.wg-config.outPath}/client_00067.conf";
    address = "10.0.0.68/24";
  };
in {
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
    networkmanager.enable = false; # Easiest to use and most distros use this by default.
    useDHCP = false;
    useNetworkd = true;
    nftables.enable = true;
    firewall = {
      enable = false;
      trustedInterfaces = ["eno1" "br-lan"];
      checkReversePath = false;
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
    netdevs."40-wg0" = wg.netdev;
    networks."40-wg0" = wg.network;

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

  time.timeZone = "Asia/Hong_Kong";

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

  # 这里只留机器自己需要的。GUI 应用、编译工具链、看 GPU 的那几个都搬去了
  # home(modules/gui、profiles/dev)—— 换一个浏览器不该需要 root + 整机重建。
  # vim 留着:系统坏掉时是以 root 身份进来修的,那时候 home 的 PATH 帮不上忙。
  # qemu 没了:profiles/virtualisation 已经装了它。
  environment.systemPackages = with pkgs; [
    vim
    wqy_microhei
    ntfs3g
    adwaita-icon-theme
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

  catppuccin.autoEnable = false;

  system.stateVersion = "24.11"; # Did you read the comment?
}
