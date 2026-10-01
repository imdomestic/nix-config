{config, pkgs, ...}: {
  boot = {
    kernelPackages = pkgs.linuxPackages_latest;
    loader = {
      efi = {
        canTouchEfiVariables = true;
        efiSysMountPoint = "/efi";
      };
      # Keep kernels on XBOOTLDR; the Windows ESP is only 300 MiB.
      systemd-boot = {
        enable = true;
        # Try a lower-resolution firmware console for the HiDPI panel.
        consoleMode = "0";
        configurationLimit = 5;
        xbootldrMountPoint = "/boot";
      };
    };
  };

  networking.networkmanager.enable = true;
  hardware = {
    enableRedistributableFirmware = true;
    graphics.enable = true;
    bluetooth.enable = true;
  };
  services.fstrim.enable = true;
  zramSwap.enable = true;
  powerManagement.enable = true;

  security.sudo-rs = {
    enable = true;
    # Preserve the shared max operator rule when replacing sudo.
    extraRules = config.security.sudo.extraRules;
  };

  # The installer supplies a prebuilt standalone home for the first GNOME login.
  systemd.services."268v-home-bootstrap" = {
    description = "Activate the prebuilt hank GNOME configuration";
    wantedBy = ["multi-user.target"];
    wants = ["nix-daemon.socket"];
    after = ["nix-daemon.socket" "systemd-user-sessions.service"];
    before = ["display-manager.service"];
    unitConfig.ConditionPathExists = [
      "/var/lib/268v-bootstrap/activate-home"
      "!/home/hank/.local/state/268v-home-ready"
    ];
    path = with pkgs; [coreutils dbus nix];
    environment = {
      HOME = "/home/hank";
      USER = "hank";
      NIX_REMOTE = "daemon";
      HOME_MANAGER_BACKUP_EXT = "pre-268v";
    };
    serviceConfig = {
      Type = "oneshot";
      User = "hank";
      RemainAfterExit = true;
      TimeoutStartSec = 600;
    };
    script = ''
      dbus-run-session /var/lib/268v-bootstrap/activate-home
      mkdir -p /home/hank/.local/state
      touch /home/hank/.local/state/268v-home-ready
    '';
  };

  programs = {
    zsh.enable = true;
    nix-index-database.comma.enable = true;
  };
  environment.systemPackages = with pkgs; [git pciutils usbutils vim];
  time.timeZone = "Asia/Shanghai";
  i18n.defaultLocale = "en_US.UTF-8";

  my = {
    tailscale = {
      enable = true;
      ssh = true;
    };
    host.useChinaMirror = false;
  };
  system.stateVersion = "26.05";
}
