{
  config,
  pkgs,
  ...
}: {
  imports = [
    ../../modules/qwen38-ninfer.nix
  ];

  boot = {
    loader = {
      systemd-boot = {
        enable = true;
        configurationLimit = 5;
        xbootldrMountPoint = "/boot";
      };
      efi = {
        # WSL cannot write firmware variables; the disk-local fallback loader
        # also keeps this installation independent from Windows Boot Manager.
        canTouchEfiVariables = false;
        efiSysMountPoint = "/efi";
      };
    };
  };

  networking = {
    networkmanager.enable = false;
    useDHCP = false;
    useNetworkd = true;
    nftables.enable = true;
  };
  systemd.network = {
    enable = true;
    networks."10-wired" = {
      matchConfig.Type = "ether";
      networkConfig = {
        DHCP = "yes";
        IPv6AcceptRA = true;
      };
      linkConfig.RequiredForOnline = "routable";
    };
  };

  hardware = {
    graphics.enable = true;
    nvidia = {
      modesetting.enable = true;
      powerManagement.enable = false;
      open = true;
      nvidiaSettings = false;
      nvidiaPersistenced = true;
      package = config.boot.kernelPackages.nvidiaPackages.production;
    };
    nvidia-container-toolkit.enable = true;
  };
  services.xserver.videoDrivers = ["nvidia"];
  nixpkgs.config.allowUnfree = true;

  services.qwen38Ninfer = {
    enable = true;
    image = "localhost/ninfer:qwen38-24g-550d0ac-36f8e80f047d";
    imageArchive = "/var/lib/qwen38/ninfer-catalog-image-20260905.tar";
  };

  # The native node receives its own Tailscale identity on first boot. The
  # inference gateway discovers that address at runtime and binds only to it.
  my.tailscale.enable = true;

  services.openssh.enable = true;
  security.sudo.wheelNeedsPassword = false;
  programs = {
    zsh.enable = true;
    nix-index-database.comma.enable = true;
  };

  environment.systemPackages = with pkgs; [
    pciutils
    nvtopPackages.nvidia
  ];

  time.timeZone = "Asia/Hong_Kong";
  system.stateVersion = "26.05";
}
