{
  pkgs,
  inputs,
  ...
}: let
  wg = import ../../../lib/wgClient.nix {inherit pkgs;} {
    conf = "${inputs.wg-config.outPath}/client_00024.conf";
    address = "10.0.0.25/24";
  };
in {
  imports = [
    ./hardware-configuration.nix
    ./dosuspend.nix
  ];

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.kernelPackages = pkgs.linuxPackages_zen;

  boot.binfmt = {
    emulatedSystems = ["aarch64-linux"];
    preferStaticEmulators = true;
  };

  networking = {
    networkmanager.enable = false;
    wireless.iwd.enable = true;

    useDHCP = false;
    useNetworkd = true;
    nameservers = ["1.1.1.1" "8.8.8.8"];
  };

  # Configure network proxy if necessary
  # networking.proxy.default = "http://127.0.0.1:7890";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  systemd.network = {
    wait-online.enable = false;
    enable = true;
    netdevs."40-wg0" = wg.netdev;
    networks."40-wg0" = wg.network;
    networks."wlan" = {
      matchConfig.Name = "wlan0";
      networkConfig = {
        DHCP = "yes";
      };
    };
  };

  time.timeZone = "Asia/Hong_Kong";

  nixpkgs.config.rocmSupport = true;

  services.xserver.enable = true;
  services.displayManager.gdm.enable = true;
  services.desktopManager.gnome.enable = true;

  services.flatpak.enable = true;
  services.spice-vdagentd.enable = true;
  services.blueman.enable = true;

  services.resolved = {
    enable = true;
    settings.Resolve.FallbackDNS = ["223.5.5.5"];
  };

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

  system.stateVersion = "25.11"; # Did you read the comment?
}
