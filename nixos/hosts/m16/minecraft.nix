{
  lib,
  pkgs,
  ...
}: let
  serverNames = ["proxy" "bedrock-proxy" "lobby" "bingo" "speedrun" "GTL"];
  proxies = ["proxy" "bedrock-proxy"];
  paperServers = ["lobby" "speedrun"];
  databasePython = pkgs.python3.withPackages (python: [python.psycopg python.pymysql]);
  backends = {
    lobby = "127.0.0.1:25568";
    bingo = "127.0.0.1:25573";
    speedrun = "127.0.0.1:25567";
    gtl = "127.0.0.1:25560";
    try = ["lobby"];
  };
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
  cmiDatabase = {
    storage.method = "mysql";
    mysql = {
      username = "mc_user";
      password = "@MC_MYSQL_PASSWORD@";
      hostname = "127.0.0.1:3306";
      database = "minecraft";
      tablePrefix = "CMI_";
      autoReconnect = true;
      useSSL = false;
      verifyServerCertificate = false;
    };
    AutoSaveInterval = 15;
    ForceSaveOnLogOut = false;
    ForceLoadOnLogIn = false;
  };
in {
  imports = [../../modules/minecraft/wuxi.nix];

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

  services.minecraft-servers = {
    dataDir = lib.mkForce "/var/lib/minecraft";
    user = lib.mkForce "minecraft";
    environmentFile = "/var/lib/minecraft-secrets/runtime.env";
    managementSystem = {
      tmux.enable = false;
      systemd-socket.enable = true;
    };
    servers = lib.mkMerge [
      (lib.genAttrs serverNames (name: {
        environment.TMPDIR = "/var/cache/minecraft/${name}";
        jvmOpts = lib.mkAfter "-Djava.io.tmpdir=/var/cache/minecraft/${name} -XX:+ExitOnOutOfMemoryError";
      }))
      (lib.genAttrs proxies (name: {
        package = lib.mkForce pkgs.velocityServers.velocity-3_5_0-SNAPSHOT-build_600;
        stopCommand = "shutdown";
        symlinks."forwarding.secret" = lib.mkForce "/var/lib/minecraft-secrets/forwarding.secret";
        files = {
          "plugins/tab/config.yml" = lib.mkForce "${../../modules/minecraft/tab-velocity-config.yml}";
          "velocity.toml".value = {
            servers = lib.mkForce backends;
            forced-hosts = lib.mkForce {"gtl.imdomestic.com" = ["gtl"];};
          };
          "plugins/LuckPerms/config.conf" = lib.mkForce {value = {};};
          "plugins/SkinsRestorer/Config.yml" = lib.mkForce {value = {};};
          "plugins/Velocircon/rcon.yml".value = {
            host = lib.mkForce "127.0.0.1";
            port = lib.mkForce (
              if name == "proxy"
              then "25575"
              else "25576"
            );
            password = lib.mkForce "@MC_RCON_PASSWORD@";
          };
        };
      }))
      (lib.genAttrs paperServers (_: {
        serverProperties = {
          server-ip = lib.mkForce "127.0.0.1";
          "rcon.password" = lib.mkForce "@MC_RCON_PASSWORD@";
        };
        files = {
          "config/paper-global.yml".value.proxies.velocity.secret = lib.mkForce "@MC_FORWARDING_SECRET@";
          "plugins/CMI/Settings/Chat.yml" = lib.mkForce "${../../modules/minecraft/cmi-Chat.yml}";
          "plugins/CMI/config.yml" = lib.mkForce "${../../modules/minecraft/cmi-config.yaml}";
          "plugins/CMI/Settings/DataBaseInfo.yml" = lib.mkForce {value = cmiDatabase;};
          "plugins/LuckPerms/config.yml".value.data = {
            address = lib.mkForce "127.0.0.1:5432";
            password = lib.mkForce "@MC_POSTGRES_PASSWORD@";
          };
          "plugins/SkinsRestorer/Config.yml" = lib.mkForce {value = {};};
        };
      }))
      {
        proxy.files."velocity.toml".value.advanced.haproxy-protocol = lib.mkForce false;
        bedrock-proxy.files."velocity.toml".value.bind = lib.mkForce "127.0.0.1:25572";
        lobby.jvmOpts = lib.mkForce "-Xms1G -Xmx2G -Djava.io.tmpdir=/var/cache/minecraft/lobby -XX:+ExitOnOutOfMemoryError";
        speedrun = {
          jvmOpts = lib.mkForce "-Xms1G -Xmx4G -Djava.io.tmpdir=/var/cache/minecraft/speedrun -XX:+ExitOnOutOfMemoryError";
          serverProperties."rcon.port" = lib.mkForce 25579;
        };
        bingo = {
          jvmOpts = lib.mkForce "-Xms1G -Xmx4G -Dluckperms.base-directory=config/luckperms -Djava.io.tmpdir=/var/cache/minecraft/bingo -XX:+ExitOnOutOfMemoryError";
          serverProperties = {
            server-ip = lib.mkForce "127.0.0.1";
            "rcon.password" = lib.mkForce "@MC_RCON_PASSWORD@";
          };
          files = {
            "config/FabricProxy-Lite.toml".value.secret = lib.mkForce "@MC_FORWARDING_SECRET@";
            "config/luckperms/luckperms.conf".value.data = {
              address = lib.mkForce "127.0.0.1:5432";
              password = lib.mkForce "@MC_POSTGRES_PASSWORD@";
            };
          };
        };
        GTL = {
          enable = true;
          package = pkgs.writeShellScriptBin "minecraft-server" ''
            exec ${pkgs.temurin-bin-17}/bin/java "$@" \
              @libraries/net/minecraftforge/forge/1.20.1-47.3.7/unix_args.txt nogui
          '';
          jvmOpts = lib.mkForce "-Xms1G -Xmx6G -Dterminal.jline=false -Dterminal.ansi=false -Djava.io.tmpdir=/var/cache/minecraft/GTL -XX:+ExitOnOutOfMemoryError";
          serverProperties = {
            allow-flight = false;
            allow-nether = true;
            broadcast-console-to-ops = true;
            broadcast-rcon-to-ops = true;
            difficulty = "easy";
            enable-command-block = false;
            enable-jmx-monitoring = false;
            enable-query = false;
            enable-rcon = false;
            enable-status = true;
            enforce-secure-profile = true;
            enforce-whitelist = false;
            entity-broadcast-range-percentage = 100;
            force-gamemode = false;
            function-permission-level = 2;
            gamemode = "survival";
            generate-structures = true;
            generator-settings = "{}";
            hardcore = false;
            hide-online-players = false;
            initial-disabled-packs = "";
            initial-enabled-packs = "vanilla";
            level-name = "world";
            level-seed = "";
            level-type = "minecraft:normal";
            max-chained-neighbor-updates = 1000000;
            max-players = 114514;
            max-tick-time = 60000;
            max-world-size = 29999984;
            motd = "LinWhite's GT Server";
            network-compression-threshold = 256;
            online-mode = false;
            op-permission-level = 4;
            player-idle-timeout = 0;
            prevent-proxy-connections = false;
            pvp = true;
            "query.port" = 25560;
            rate-limit = 0;
            "rcon.port" = 25575;
            require-resource-pack = false;
            resource-pack = "";
            resource-pack-prompt = "";
            resource-pack-sha1 = "";
            server-ip = "127.0.0.1";
            server-port = 25560;
            simulation-distance = 10;
            spawn-animals = true;
            spawn-monsters = true;
            spawn-npcs = true;
            spawn-protection = 16;
            sync-chunk-writes = true;
            text-filtering-config = "";
            use-native-transport = true;
            view-distance = 16;
            white-list = false;
          };
          files."config/proxy-compatible-forge.toml".value = {
            version = 2.0;
            forwarding = {
              enabled = true;
              mode = "MODERN";
              secret = "@MC_FORWARDING_SECRET@";
              approvedProxyHosts = [];
            };
            crossStitch = {
              enabled = true;
              forceWrappedArguments = [];
              forceWrapVanillaArguments = false;
            };
            debug = {
              enabled = false;
              disabledMixins = [];
            };
            advanced.modernForwardingVersion = "NO_OVERRIDE";
          };
          extraStartPre = ''
            test -s libraries/net/minecraftforge/forge/1.20.1-47.3.7/unix_args.txt
            test -s world/level.dat
          '';
        };
      }
    ];
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
  });
  systemd.slices.minecraft.sliceConfig = {
    MemoryHigh = "18G";
    MemoryMax = "20G";
  };
  systemd.services =
    {
      minecraft-postgresql-credentials = databaseCredentials "postgresql";
      minecraft-mysql-credentials = databaseCredentials "mysql";
    }
    // lib.genAttrs (map (name: "minecraft-server-${name}") serverNames) (unit: let
      name = lib.removePrefix "minecraft-server-" unit;
    in {
      unitConfig.ConditionPathExists = "/var/lib/minecraft/.restored";
      requires = ["minecraft-postgresql-credentials.service" "minecraft-mysql-credentials.service"];
      after = ["minecraft-postgresql-credentials.service" "minecraft-mysql-credentials.service"];
      serviceConfig = {
        Slice = "minecraft.slice";
        CacheDirectory = "minecraft/${name}";
        RestartSec = 10;
        IPAddressDeny = ["10.0.0.66/32" "100.64.0.4/32"];
      };
    });
}
