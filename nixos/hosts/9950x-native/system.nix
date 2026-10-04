{
  config,
  lib,
  pkgs,
  ...
}: let
  prepareWindowsLoader = ''
    windowsBoot=/windows-efi/EFI/Microsoft/Boot
    if [ -f "$windowsBoot/bootmgfw.efi" ]; then
      ${pkgs.coreutils}/bin/mv -f "$windowsBoot/bootmgfw.efi" "$windowsBoot/windows.efi"
    fi
    test -s "$windowsBoot/windows.efi"
    windowsFallback=/windows-efi/EFI/Boot
    if [ -f "$windowsFallback/bootx64.efi" ] && ${pkgs.diffutils}/bin/cmp -s "$windowsFallback/bootx64.efi" "$windowsBoot/windows.efi"; then
      ${pkgs.coreutils}/bin/mv -f "$windowsFallback/bootx64.efi" "$windowsFallback/windows.efi"
    fi
  '';
in {
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
          search --no-floppy --fs-uuid --set=root 8C8A-383D
          chainloader /EFI/Microsoft/Boot/windows.efi
        }
      '';
      extraInstallCommands = prepareWindowsLoader;
    };
    efi = {
      canTouchEfiVariables = false;
      efiSysMountPoint = "/boot";
    };
  };

  networking.networkmanager = {
    enable = true;
    settings.main.no-auto-default = "*";
    wifi.powersave = false;
    ensureProfiles = {
      environmentFiles = ["/var/lib/NetworkManager/9950x-wifi.env"];
      profiles."9950x-ethernet" = {
        connection = {
          id = "9950x-ethernet";
          type = "ethernet";
          autoconnect = true;
          autoconnect-priority = 100;
          autoconnect-retries = 0;
          multi-connect = 3;
        };
        ipv4 = {
          method = "auto";
          dhcp-client-id = "mac";
        };
        ipv6.method = "auto";
      };
      profiles."9950x-wifi" = {
        connection = {
          id = "9950x-wifi";
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
  networking.nftables.enable = true;

  hardware.nvidia = {
    modesetting.enable = true;
    open = true;
    nvidiaSettings = true;
    package = config.boot.kernelPackages.nvidiaPackages.production;
  };
  services.xserver.videoDrivers = ["nvidia"];
  nixpkgs.config.allowUnfree = true;
  my.host.useChinaMirror = false;

  services = {
    displayManager.gdm.autoSuspend = false;
    pipewire.alsa.enable = true;
    logind.settings.Login.IdleAction = "ignore";
    avahi = {
      enable = true;
      openFirewall = true;
      publish = {
        enable = true;
        addresses = true;
        workstation = true;
      };
    };
    openssh.settings = {
      PasswordAuthentication = lib.mkForce false;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = lib.mkForce "prohibit-password";
    };
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
  systemd.services."9950x-boot-entries" = {
    description = "Keep Windows boot access in the GRUB menu";
    wantedBy = ["multi-user.target"];
    after = ["local-fs.target"];
    unitConfig = {
      ConditionPathIsMountPoint = "/sys/firmware/efi/efivars";
      RequiresMountsFor = ["/boot" "/windows-efi"];
    };
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      StateDirectory = "9950x-boot-entries";
      StateDirectoryMode = "0700";
      UMask = "0077";
    };
    script =
      prepareWindowsLoader
      + ''
        test -s /boot/EFI/BOOT/BOOTX64.EFI
        shopt -s nullglob
        for variable in /sys/firmware/efi/efivars/Boot????-8be4df61-93ca-11d2-aa0d-00e098032b8c; do
          name=''${variable##*/}
          name=''${name%%-*}
          entry="$(${pkgs.efibootmgr}/bin/efibootdump "$name")"
          case "$entry" in
            "$name: "*"Windows Boot Manager HD(1,GPT,d75bbc8d-492f-4250-931e-d2b84cc4982a,"*)
              ${pkgs.coreutils}/bin/cp "$variable" "$STATE_DIRECTORY/$name"
              ${pkgs.efibootmgr}/bin/efibootmgr --bootnum "''${name#Boot}" --delete-bootnum
              ;;
          esac
        done
      '';
  };

  security.rtkit.enable = true;
  security.sudo.wheelNeedsPassword = false;
  users.users.linwhite.hashedPasswordFile = "/var/lib/user-passwords/linwhite";
  programs.nix-index-database.comma.enable = true;
  environment.systemPackages = with pkgs; [pciutils efibootmgr nvtopPackages.nvidia];
  time.timeZone = "Asia/Tokyo";
  system.stateVersion = "26.05";
}
