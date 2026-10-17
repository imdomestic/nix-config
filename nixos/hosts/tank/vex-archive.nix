{pkgs, ...}: {
  users.groups.vex-archive.gid = 970;
  users.users.vex-archive = {
    isSystemUser = true;
    uid = 979;
    group = "vex-archive";
    home = "/var/lib/vex-archive";
    createHome = true;
    shell = pkgs.bashInteractive;
    hashedPassword = "!";
    openssh.authorizedKeys.keys = [
      ''restrict,from="100.64.0.43" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIemPenLpJ0hcmrlte+me/fp03TUty7NxOIEB+sHZqg vexd-archive-at-encore''
    ];
  };

  environment.systemPackages = [pkgs.rsync];
  systemd.tmpfiles.rules = [
    "d /var/lib/vex-archive 0700 vex-archive vex-archive -"
    "d /srv/archive/vex/projects 0750 vex-archive vex-archive -"
    "d /srv/archive/vex/projects/chorus 0750 vex-archive vex-archive -"
    "d /srv/archive/vex/projects/chorus/snapshots 0750 vex-archive vex-archive -"
    "d /srv/archive/vex/projects/chorus/worlds 0750 vex-archive vex-archive -"
    "d /srv/archive/vex/projects/chorus/packs 0750 vex-archive vex-archive -"
  ];

  # 专用账号只读取自己的公钥文件，来源限制随公钥生效。
  services.openssh.extraConfig = ''
    Match User vex-archive
      AuthorizedKeysFile /etc/ssh/authorized_keys.d/vex-archive
      AuthenticationMethods publickey
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      DisableForwarding yes
      PermitTTY no
      PermitUserRC no
    Match all
  '';
}
