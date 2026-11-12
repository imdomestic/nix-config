{
  config,
  lib,
  pkgs,
  ...
}: let
  windowsEntry = pkgs.writeText "seraph-windows.conf" config.boot.loader.systemd-boot.extraEntries."windows.conf";
  prepareWindowsLoader = ''
    ${pkgs.util-linux}/bin/mountpoint -q /boot
    ${pkgs.util-linux}/bin/mountpoint -q /windows-efi
    windowsBoot=/windows-efi/EFI/Microsoft/Boot
    if [ -f "$windowsBoot/bootmgfw.efi" ]; then
      ${pkgs.coreutils}/bin/mv -f "$windowsBoot/bootmgfw.efi" "$windowsBoot/windows.efi"
    fi
    test -s "$windowsBoot/windows.efi"
    windowsFallback=/windows-efi/EFI/Boot
    if [ -f "$windowsFallback/bootx64.efi" ] && ${pkgs.diffutils}/bin/cmp -s "$windowsFallback/bootx64.efi" "$windowsBoot/windows.efi"; then
      ${pkgs.coreutils}/bin/mv -f "$windowsFallback/bootx64.efi" "$windowsFallback/windows.efi"
    fi
    # systemd-boot 只能读取自己的 ESP；保留重命名绕过固件抢启动项的行为。
    ${pkgs.coreutils}/bin/install -d /boot/EFI/Microsoft /boot/loader/entries
    ${pkgs.coreutils}/bin/cp -r /windows-efi/EFI/Microsoft/. /boot/EFI/Microsoft/
    ${pkgs.coreutils}/bin/install -m 0600 ${windowsEntry} /boot/loader/entries/windows.conf
  '';
in {
  # 安装、密钥注册及双系统恢复步骤见 docs/runbooks/seraph-secure-boot.md。
  boot.lanzaboote = {
    # 先验证普通 systemd-boot 启动，确认后再启用签名。
    enable = false;
    pkiBundle = "/var/lib/sbctl";
    configurationLimit = 5;
    allowUnsigned = false;
    autoEnrollKeys.enable = false;
    settings.editor = false;
  };
  boot.loader = {
    timeout = 5;
    grub.enable = false;
    # 开启 Lanzaboote 时，它会替代原生 systemd-boot 安装器。
    systemd-boot = {
      enable = !config.boot.lanzaboote.enable;
      configurationLimit = 5;
      editor = false;
      extraInstallCommands = prepareWindowsLoader;
      extraEntries."windows.conf" = ''
        title Windows
        efi /EFI/Microsoft/Boot/windows.efi
        sort-key o_windows
      '';
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
      environmentFiles = ["/var/lib/NetworkManager/seraph-wifi.env"];
      profiles."seraph-ethernet" = {
        connection = {
          id = "seraph-ethernet";
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
      profiles."seraph-wifi" = {
        connection = {
          id = "seraph-wifi";
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
  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [25565];

  nixpkgs.config.allowUnfree = true;

  services = {
    tailscale.extraSetFlags = ["--hostname=${config.networking.hostName}"];
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
  # 原生 systemd-boot 模块停用后，由包装器安装其 Windows entry。
  system.build.installBootLoader = lib.mkIf config.boot.lanzaboote.enable (lib.mkForce (pkgs.writeShellScript "seraph-install-bootloader" ''
    set -euo pipefail
    test -s ${lib.escapeShellArg (toString config.boot.lanzaboote.privateKeyFile)}
    test -s ${lib.escapeShellArg (toString config.boot.lanzaboote.publicKeyFile)}
    ${prepareWindowsLoader}
    exec ${config.boot.loader.external.installHook} "$@"
  ''));
  systemd.services."seraph-boot-entries" = {
    description = "Keep Windows boot access in the systemd-boot menu";
    wantedBy = ["multi-user.target"];
    after = ["local-fs.target"];
    unitConfig = {
      ConditionPathIsMountPoint = "/sys/firmware/efi/efivars";
      RequiresMountsFor = ["/boot" "/windows-efi"];
    };
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      StateDirectory = "seraph-boot-entries";
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
            "$name: "*"UEFI:CD/DVD Drive BBS(129,,0x0)"|"$name: "*"UEFI:Removable Device BBS(130,,0x0)"|"$name: "*"UEFI:Network Device BBS(131,,0x0)")
              ${pkgs.coreutils}/bin/cp "$variable" "$STATE_DIRECTORY/$name"
              ${pkgs.efibootmgr}/bin/efibootmgr --bootnum "''${name#Boot}" --delete-bootnum
              ;;
          esac
        done
      '';
  };

  security.sudo.wheelNeedsPassword = false;
  users.users.linwhite.hashedPasswordFile = "/var/lib/user-passwords/linwhite";
  programs.nix-index-database.comma.enable = true;
  fonts.packages = with pkgs; [
    noto-fonts-cjk-sans
    noto-fonts-cjk-serif
  ];
  environment.systemPackages = with pkgs; [pciutils efibootmgr nvtopPackages.nvidia sbctl];
  time.timeZone = "Asia/Tokyo";
  system.stateVersion = "26.05";
}
