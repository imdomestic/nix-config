{
  lib,
  pkgs,
  ...
}: let
  databasePython = pkgs.python3.withPackages (python: [python.psycopg python.pymysql]);
  databaseCredentials = database: {
    description = "Minecraft ${database} credentials";
    requires = ["${database}.service"];
    after = ["${database}.service"];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      User =
        if database == "postgresql"
        then "postgres"
        else "root";
      LoadCredential = ["database.json:/var/lib/minecraft-secrets/database.json"];
      ExecStart = "${databasePython}/bin/python ${./minecraft-database.py} ${database}";
    };
  };
in {
  services.postgresql = {
    enable = true;
    package = pkgs.postgresql_16;
    enableTCPIP = true;
    settings.listen_addresses = lib.mkForce "127.0.0.1";
    ensureDatabases = ["minecraft" "luckperms"];
    ensureUsers = [
      {
        name = "minecraft";
        ensureDBOwnership = true;
        ensureClauses.login = true;
      }
    ];
    authentication = lib.mkForce ''
      local all all peer
      host minecraft,luckperms minecraft 127.0.0.1/32 scram-sha-256
    '';
  };
  services.mysql = {
    enable = true;
    package = pkgs.mariadb;
    settings.mysqld.bind-address = "127.0.0.1";
    ensureDatabases = ["minecraft"];
    ensureUsers = [
      {
        name = "mc_user";
        ensurePermissions."minecraft.*" = "ALL PRIVILEGES";
      }
    ];
  };

  users.groups.minecraft.gid = 982;
  users.users.minecraft = {
    uid = 988;
    isSystemUser = true;
    group = "minecraft";
    home = "/var/lib/minecraft";
    createHome = false;
  };
  users.users.hank.extraGroups = ["minecraft"];
  users.users.linwhite.extraGroups = ["minecraft"];
  systemd.tmpfiles.rules = [
    "d /var/lib/minecraft-secrets 0750 root minecraft -"
    "z /var/lib/minecraft-secrets/forwarding.secret 0640 root minecraft -"
  ];
  networking.firewall.interfaces = lib.genAttrs ["wlo1" "tailscale0"] (_: {
    allowedTCPPorts = [25565];
    allowedUDPPorts = [19132];
  }) // {
    tailscale0.allowedTCPPorts = [25565 47984 47989 47990 48010];
    tailscale0.allowedUDPPorts = [19132 47998 47999 48000 48002 48010];
  };
  systemd.services = {
    minecraft-postgresql-credentials = databaseCredentials "postgresql";
    minecraft-mysql-credentials = databaseCredentials "mysql";
  };
}
