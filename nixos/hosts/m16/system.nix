{
  config,
  pkgs,
  ...
}: let
  prepareWindowsLoader = ''
    windowsBoot=/efi/EFI/Microsoft/Boot
    if [ -f "$windowsBoot/bootmgfw.efi" ]; then
      ${pkgs.coreutils}/bin/mv -f "$windowsBoot/bootmgfw.efi" "$windowsBoot/windows.efi"
    fi
    test -s "$windowsBoot/windows.efi"
  '';
in {
  imports = [
    ../../modules/keyd
    ../../modules/nerdfonts
  ];

  boot.loader = {
    timeout = 5;
    grub = {
      enable = true;
      device = "nodev";
      efiSupport = true;
      efiInstallAsRemovable = true;
      configurationLimit = 5;
      default = 0;
      extraEntries = ''
        menuentry "Windows" --class windows {
          insmod part_gpt
          insmod fat
          insmod chain
          search --no-floppy --fs-uuid --set=root 6219-21FA
          chainloader /EFI/Microsoft/Boot/windows.efi
        }
      '';
      extraInstallCommands = prepareWindowsLoader;
    };
    efi = {
      canTouchEfiVariables = false;
      efiSysMountPoint = "/efi";
    };
  };

  networking = {
    networkmanager = {
      enable = true;
      wifi.powersave = false;
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
    AllowHybridSleep = false;
    AllowSuspendThenHibernate = false;
  };
  systemd.targets = {
    sleep.enable = false;
    suspend.enable = false;
    hibernate.enable = false;
    hybrid-sleep.enable = false;
    suspend-then-hibernate.enable = false;
  };
  programs.dconf.profiles.user.databases = [
    {
      lockAll = true;
      settings."org/gnome/settings-daemon/plugins/power" = {
        sleep-inactive-ac-type = "nothing";
        sleep-inactive-battery-type = "nothing";
      };
    }
  ];
  systemd.services.m16-boot-entries = {
    description = "Keep Windows boot access in the GRUB menu";
    wantedBy = ["multi-user.target"];
    after = ["local-fs.target"];
    unitConfig = {
      ConditionPathIsMountPoint = "/sys/firmware/efi/efivars";
      RequiresMountsFor = ["/efi"];
    };
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      StateDirectory = "m16-boot-entries";
      StateDirectoryMode = "0700";
      UMask = "0077";
    };
    script =
      prepareWindowsLoader
      + ''
        test -s /efi/EFI/BOOT/BOOTX64.EFI
        shopt -s nullglob
        for variable in /sys/firmware/efi/efivars/Boot????-8be4df61-93ca-11d2-aa0d-00e098032b8c; do
          name=''${variable##*/}
          name=''${name%%-*}
          entry="$(${pkgs.efibootmgr}/bin/efibootdump "$name")"
          case "$entry" in
            "$name: "*"Windows Boot Manager HD(1,GPT,8762fad7-cfcb-4eae-8bf0-4315bef44901,"*)
              ${pkgs.coreutils}/bin/cp "$variable" "$STATE_DIRECTORY/$name"
              ${pkgs.coreutils}/bin/rm "$variable"
              ;;
          esac
        done
      '';
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
