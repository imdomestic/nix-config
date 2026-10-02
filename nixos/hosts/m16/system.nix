{
  config,
  pkgs,
  ...
}: {
  imports = [
    ../../modules/keyd
    ../../modules/nerdfonts
  ];

  boot.loader = {
    systemd-boot = {
      enable = true;
      configurationLimit = 5;
      xbootldrMountPoint = "/boot";
    };
    efi = {
      canTouchEfiVariables = true;
      efiSysMountPoint = "/efi";
    };
  };

  networking = {
    networkmanager = {
      enable = true;
      ensureProfiles = {
        environmentFiles = ["/var/lib/NetworkManager/m16-wifi.env"];
        profiles.m16-wifi = {
          connection = {
            id = "m16-wifi";
            type = "wifi";
            autoconnect = true;
            autoconnect-retries = 0;
          };
          wifi = {
            mode = "infrastructure";
            ssid = "$INSTALLER_WIFI_SSID";
          };
          wifi-security = {
            key-mgmt = "wpa-psk";
            psk = "$INSTALLER_WIFI_PASSWORD";
          };
          ipv4.method = "auto";
          ipv6.method = "auto";
        };
      };
    };
    nftables.enable = true;
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
  nixpkgs.config.allowUnfree = true;
  my.host.useChinaMirror = false;
  virtualisation.podman.enable = true;

  i18n.inputMethod.ibus.engines = [pkgs.ibus-engines.libpinyin];
  services = {
    displayManager.gdm = {
      enable = true;
      autoSuspend = false;
    };
    desktopManager.gnome.enable = true;
    pipewire = {
      enable = true;
      alsa.enable = true;
      pulse.enable = true;
    };
    logind.settings.Login = {
      HandleLidSwitch = "ignore";
      HandleLidSwitchExternalPower = "ignore";
      HandleLidSwitchDocked = "ignore";
      IdleAction = "ignore";
    };
    avahi = {
      enable = true;
      openFirewall = true;
      publish = {
        enable = true;
        addresses = true;
        workstation = true;
      };
    };
    # GNOME 使用 Intel 核显，将独立显卡留给计算任务。
    udev.extraRules = ''
      SUBSYSTEM=="drm", KERNEL=="card[0-9]*|renderD[0-9]*", ATTRS{vendor}=="0x8086", ATTRS{device}=="0x46a6", TAG+="mutter-device-preferred-primary"
      SUBSYSTEM=="drm", KERNEL=="card[0-9]*|renderD[0-9]*", ATTRS{vendor}=="0x10de", ATTRS{device}=="0x2520", TAG+="mutter-device-ignore"
    '';
  };
  systemd.sleep.settings.Sleep = {
    AllowSuspend = false;
    AllowHibernation = false;
  };

  security = {
    rtkit.enable = true;
    sudo.wheelNeedsPassword = false;
  };
  users.users = {
    linwhite.hashedPasswordFile = "/var/lib/user-passwords/linwhite";
    hank.hashedPasswordFile = "/var/lib/user-passwords/hank";
  };
  programs = {
    zsh.enable = true;
    nix-index-database.comma.enable = true;
  };
  environment.systemPackages = with pkgs; [
    pciutils
    nvtopPackages.nvidia
    btop-cuda
  ];

  time.timeZone = "Asia/Tokyo";
  system.stateVersion = "26.05";
}
