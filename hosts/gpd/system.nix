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

  time.timeZone = "Asia/Hong_Kong";

  users.users.linwhite = {
    isNormalUser = true;
    extraGroups = ["wheel"];
    packages = with pkgs; [
      tree
    ];
  };

  security.sudo.wheelNeedsPassword = false;

  nixpkgs.config.rocmSupport = true;

  services.xserver.enable = true;
  services.displayManager.gdm.enable = true;
  services.desktopManager.gnome.enable = true;
  # services.xserver.displayManager.lightdm = {
  #   enable = true;
  #   extraConfig = ''
  #     display-setup-script=xrandr --output eDP-1 --rotate right
  #     '';
  # };

  services.flatpak.enable = true;
  services.spice-vdagentd.enable = true;
  services.blueman.enable = true;

  services.resolved = {
    enable = true;
    settings.Resolve.FallbackDNS = ["223.5.5.5"];
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

  services.pipewire = {
    enable = true;
    pulse.enable = true;
  };

  # 这里只留机器自己需要的。GUI 应用、编译工具链、看 GPU 的那几个都搬去了
  # home(home/linwhite/gpd.nix、profiles/dev)—— 换一个浏览器不该需要 root + 整机重建。
  # vim 留着:系统坏掉时是以 root 身份进来修的,那时候 home 的 PATH 帮不上忙。
  environment.systemPackages = with pkgs; [
    vim
    wqy_microhei
    ntfs3g
    qemu
    adwaita-icon-theme
  ];

  fonts.packages = with pkgs; [
    noto-fonts-cjk-sans
    noto-fonts-cjk-serif
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

  system.stateVersion = "26.05";
}
