{
  config,
  pkgs,
  ...
}: {
  assertions = [
    {
      assertion = config.services.tailscale.enable && config.my.host.tsName != null;
      message = "linwhite 的 SMB 共享需要 Tailscale 与主机注册名称。";
    }
    {
      assertion = builtins.elem "linwhite" config.my.host.usernames;
      message = "linwhite 的 SMB 共享需要本机 linwhite 账户。";
    }
  ];

  services.samba = {
    enable = true;
    openFirewall = false;
    nmbd.enable = false;
    winbindd.enable = false;
    settings = {
      global = {
        "server string" = "${config.my.host.name} linwhite home";
        "server min protocol" = "SMB3_00";
        # 使用 Tailscale 地址范围，Samba 只绑定名称解析得到的本机地址。
        interfaces = ["${config.my.host.tsName}/10"];
        "bind interfaces only" = true;
        "smb ports" = "445";
        # aegis 的地址已通过 Tailscale 状态核实。
        "hosts allow" = ["100.64.0.25"];
        "hosts deny" = ["ALL"];
        "load printers" = false;
        "disable spoolss" = true;
        "vfs objects" = ["catia" "fruit" "streams_xattr"];
        "fruit:metadata" = "stream";
        "fruit:nfs_aces" = false;
      };
      "${config.my.host.name}-linwhite" = {
        path = config.users.users.linwhite.home;
        browseable = true;
        "read only" = false;
        "guest ok" = false;
        "valid users" = ["linwhite"];
        "force user" = "linwhite";
        "create mask" = "0600";
        "directory mask" = "0700";
      };
    };
  };

  systemd.services.linwhite-smb-password = {
    description = "Provision linwhite SMB credentials";
    before = ["samba-smbd.service"];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      StateDirectory = "linwhite-smb";
      StateDirectoryMode = "0700";
      UMask = "0077";
    };
    script = ''
      if [ ! -s "$STATE_DIRECTORY/password" ]; then
        ${pkgs.openssl}/bin/openssl rand -hex 32 > "$STATE_DIRECTORY/password"
      fi
      password="$(${pkgs.coreutils}/bin/cat "$STATE_DIRECTORY/password")"
      printf '%s\n%s\n' "$password" "$password" | ${config.services.samba.package}/bin/smbpasswd -s -a linwhite
    '';
  };
  systemd.services.samba-smbd = {
    requires = ["linwhite-smb-password.service"];
    after = ["linwhite-smb-password.service"];
  };

  my.tailscale.bindServices = ["samba-smbd"];
  my.tailscale.guardedTCPServices.samba-smbd = [445];
  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [445];
  networking.nftables.tables.linwhite-smb-clients = {
    family = "inet";
    content = ''
      chain input {
        type filter hook input priority -11; policy accept;
        iifname "tailscale0" ip saddr != 100.64.0.25 tcp dport 445 counter drop
        iifname "tailscale0" meta nfproto ipv6 tcp dport 445 counter drop
      }
    '';
  };
}
