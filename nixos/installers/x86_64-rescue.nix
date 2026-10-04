{
  lib,
  pkgs,
  modulesPath,
  ...
}: let
  authorizedKeys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAVka3wlxrH8v1fFxiTGxd8cnoAtbLyWDrb5xibOtDg4 linwhite@linwhite.top"
  ];
in {
  imports = [
    (modulesPath + "/installer/cd-dvd/installation-cd-minimal.nix")
    ./grub-iso.nix
    ./usb-image.nix
  ];

  networking.hostName = "nixos-rescue";
  networking.networkmanager.settings.main.no-auto-default = "*";
  networking.networkmanager.wifi.powersave = false;
  networking.networkmanager.ensureProfiles = {
    # Wi-Fi 凭据在本机写入 ISO，构建和 Git 仓库只包含变量名称。
    environmentFiles = ["/iso/installer-network.env"];
    profiles.rescue-ethernet = {
      connection = {
        id = "rescue-ethernet";
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
    profiles.installer-wifi = {
      connection = {
        id = "installer-wifi";
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

  services.openssh = {
    enable = true;
    openFirewall = true;
    settings = {
      PermitRootLogin = "prohibit-password";
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
    };
  };
  systemd.services.sshd.wantedBy = lib.mkForce ["multi-user.target"];
  users.users.root.openssh.authorizedKeys.keys = authorizedKeys;
  users.users.nixos.openssh.authorizedKeys.keys = authorizedKeys;

  services.avahi = {
    enable = true;
    openFirewall = true;
    publish = {
      enable = true;
      addresses = true;
      workstation = true;
    };
  };

  services.logind.settings.Login = {
    HandleLidSwitch = "ignore";
    HandleLidSwitchExternalPower = "ignore";
    HandleLidSwitchDocked = "ignore";
    IdleAction = "ignore";
  };
  systemd.sleep.settings.Sleep = {
    AllowSuspend = false;
    AllowHibernation = false;
    AllowHybridSleep = false;
    AllowSuspendThenHibernate = false;
  };

  environment.systemPackages = with pkgs; [
    efibootmgr
    gptfdisk
    ntfs3g
    nvme-cli
    smartmontools
  ];
  nix.settings.experimental-features = ["nix-command" "flakes"];
  time.timeZone = "Asia/Tokyo";
  boot.kernelParams = ["console=ttyS0,115200" "console=tty0"];
  boot.zfs.forceImportRoot = false;
  boot.loader.timeout = lib.mkForce 5;
  boot.loader.grub.memtest86.enable = lib.mkForce false;
  isoImage.volumeID = "NIXOS_RESCUE";
  isoImage.appendToMenuLabel = " Rescue";
  isoImage.forceTextMode = true;
  isoImage.squashfsCompression = "zstd -Xcompression-level 6";

  services.getty.helpLine = lib.mkForce ''
    NixOS x86_64 rescue and installer
    Ethernet: automatic DHCP
    Wi-Fi profile: installer-wifi
    SSH: ssh root@nixos-rescue.local
    IP addresses: ip -brief address
    Network status: nmcli device status
  '';
}
