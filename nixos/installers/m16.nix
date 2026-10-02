{lib, modulesPath, ...}: let
  authorizedKeys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAVka3wlxrH8v1fFxiTGxd8cnoAtbLyWDrb5xibOtDg4 linwhite@linwhite.top"
  ];
in {
  imports = [
    (modulesPath + "/installer/cd-dvd/installation-cd-minimal.nix")
  ];

  networking.hostName = "m16-installer";
  networking.networkmanager.ensureProfiles = {
    # Wi-Fi 凭据在本机写入 ISO，构建和 Git 仓库只包含变量名称。
    environmentFiles = ["/iso/installer-network.env"];
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
    IdleAction = "ignore";
  };
  systemd.sleep.settings.Sleep = {
    AllowSuspend = false;
    AllowHibernation = false;
  };

  nix.settings.experimental-features = ["nix-command" "flakes"];
  boot.kernelParams = ["console=ttyS0,115200" "console=tty0"];
  boot.loader.timeout = lib.mkForce 5;
  isoImage.volumeID = "NIXOS_M16";
  isoImage.squashfsCompression = "zstd -Xcompression-level 6";

  services.getty.helpLine = lib.mkForce ''
    M16 NixOS installer
    Wi-Fi profile: installer-wifi
    SSH: ssh root@m16-installer.local
    IP addresses: ip -brief address
    Network status: nmcli device status
  '';
}
