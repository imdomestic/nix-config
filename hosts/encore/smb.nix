{
  config,
  pkgs,
  ...
}: {
  my.linwhiteSmb = {
    extraClientAddresses = ["100.64.0.20"];
    extraUsers = ["ruin"];
  };

  users.groups.ruin = {};
  users.users.ruin = {
    isSystemUser = true;
    group = "ruin";
    shell = pkgs.shadow;
    createHome = false;
  };

  systemd.services.ruin-smb-password = {
    description = "Provision ruin SMB credentials";
    before = ["samba-smbd.service"];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      StateDirectory = "linwhite-smb";
      StateDirectoryMode = "0700";
      UMask = "0077";
    };
    script = ''
      if [ ! -s "$STATE_DIRECTORY/ruin-password" ]; then
        ${pkgs.openssl}/bin/openssl rand -hex 32 > "$STATE_DIRECTORY/ruin-password"
      fi
      password="$(${pkgs.coreutils}/bin/cat "$STATE_DIRECTORY/ruin-password")"
      printf '%s\n%s\n' "$password" "$password" | ${config.services.samba.package}/bin/smbpasswd -s -a ruin
    '';
  };
  systemd.services.samba-smbd = {
    requires = ["ruin-smb-password.service"];
    after = ["ruin-smb-password.service"];
  };
}
