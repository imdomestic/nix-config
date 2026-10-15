{pkgs, ...}: {
  users.groups.chorus-archive = {};
  users.users.chorus-archive = {
    isSystemUser = true;
    group = "chorus-archive";
    home = "/var/lib/chorus-archive";
    createHome = true;
    shell = pkgs.bashInteractive;
    hashedPassword = "!";
    openssh.authorizedKeys.keys = [
      ''restrict,from="100.64.0.43" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIemPenLpJ0hcmrlte+me/fp03TUty7NxOIEB+sHZqg chorusd-archive-at-encore''
    ];
  };

  environment.systemPackages = [pkgs.rsync];
  systemd.tmpfiles.rules = [
    "d /var/lib/chorus-archive 0700 chorus-archive chorus-archive -"
    "d /srv/archive/chorus/snapshots 0750 chorus-archive chorus-archive -"
    "d /srv/archive/chorus/assets 0750 chorus-archive chorus-archive -"
    "d /srv/archive/chorus/packs 0750 chorus-archive chorus-archive -"
  ];

  # 专用账号只读取自己的公钥文件，来源限制随公钥生效。
  services.openssh.extraConfig = ''
    Match User chorus-archive
      AuthorizedKeysFile /etc/ssh/authorized_keys.d/chorus-archive
      AuthenticationMethods publickey
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      DisableForwarding yes
      PermitTTY no
      PermitUserRC no
    Match all
  '';
}
