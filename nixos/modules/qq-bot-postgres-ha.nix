{
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.qq-bot-postgres-ha;

  pgAutoFailover = pkgs.postgresql17Packages.pg_auto_failover.overrideAttrs (old: {
    patches =
      (old.patches or [])
      ++ [
        ./patches/pg-auto-failover-int-string-lifetime.patch
      ];
  });
  postgres = pkgs.postgresql_17.withPackages (postgresPackages: [
    pgAutoFailover
    postgresPackages.pgvector
  ]);
  openssl = pkgs.openssl.bin;
  passwordFile =
    if cfg.passwordFile == null
    then "/dev/null"
    else cfg.passwordFile;
  monitorUri = "postgres://autoctl_node@${cfg.monitor.hostname}:${toString cfg.monitor.port}/pg_auto_failover?sslmode=require";
  monitorConfigPath = "${cfg.monitor.stateDir}/config/pg_autoctl${cfg.monitor.dataDir}/pg_autoctl.cfg";
  nodeConfigPath = "${cfg.node.stateDir}/config/pg_autoctl${cfg.node.dataDir}/pg_autoctl.cfg";

  waitForAddress = address: ''
    found=0
    for _ in $(seq 1 90); do
      if ip -4 -o address show dev tailscale0 | grep -Fq "${address}/"; then
        found=1
        break
      fi
      sleep 2
    done
    if [ "$found" -ne 1 ]; then
      echo "Tailscale address ${address} did not become ready" >&2
      exit 1
    fi
  '';

  monitorHba = pkgs.writeText "qq-bot-postgres-monitor-hba.conf" ''
    # Local administration is limited to the postgres OS account.
    local all postgres peer
    local all all reject

    # Keepers authenticate through their exact Tailscale identities. Tailscale
    # provides peer authentication; PostgreSQL still requires TLS encryption.
    ${lib.concatMapStringsSep "\n" (address: ''
        hostssl "pg_auto_failover" "autoctl_node" ${address}/32 trust
      '')
      cfg.peerAddresses}

    host all all 0.0.0.0/0 reject
    host all all ::0/0 reject
  '';
  monitorPostgresConfig = pkgs.writeText "qq-bot-postgres-monitor-local.conf" ''
    listen_addresses = '${cfg.monitor.hostname}'
    hba_file = '${cfg.monitor.dataDir}/qq-bot-ha-pg_hba.conf'
    password_encryption = 'scram-sha-256'
    ssl_min_protocol_version = 'TLSv1.2'
    unix_socket_directories = '/run/postgresql'
  '';
  nodeHba = pkgs.writeText "qq-bot-postgres-node-access.conf" ''
    # These rules are loaded before initdb's permissive local bootstrap rules.
    local all postgres peer
    local all all reject
    host all all 127.0.0.1/32 reject
    host all all ::1/128 reject

    # The bot always originates on h610 and must use TLS plus SCRAM.
    hostssl "qq_bot" "qq_bot" ${cfg.applicationClientCidr} scram-sha-256
  '';
  nodePostgresConfig = pkgs.writeText "qq-bot-postgres-node-local.conf" ''
    password_encryption = 'scram-sha-256'
    ssl_min_protocol_version = 'TLSv1.2'
    unix_socket_directories = '/run/postgresql'

    # A long-offline peer must require a fresh base backup instead of filling
    # the smaller h610 disk with unbounded replication-slot WAL.
    wal_keep_size = '${cfg.node.walKeepSize}'
    max_slot_wal_keep_size = '${cfg.node.maxSlotWalKeepSize}'
    max_wal_size = '${cfg.node.maxWalSize}'
    min_wal_size = '${cfg.node.minWalSize}'

    log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
    log_rotation_age = '1d'
    log_rotation_size = '100MB'
    log_truncate_on_rotation = on
    idle_in_transaction_session_timeout = '5min'
  '';

  monitorPrepare = pkgs.writeShellApplication {
    name = "qq-bot-postgres-monitor-prepare";
    runtimeInputs = [
      pgAutoFailover
      postgres
      openssl
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.iproute2
    ];
    text = ''
      set -euo pipefail
      umask 0077

      ${waitForAddress cfg.monitor.hostname}

      if [ ! -f ${lib.escapeShellArg monitorConfigPath} ]; then
        pg_autoctl create monitor \
          --pgdata=${lib.escapeShellArg cfg.monitor.dataDir} \
          --pgport=${toString cfg.monitor.port} \
          --pgctl=${postgres}/bin/pg_ctl \
          --hostname=${lib.escapeShellArg cfg.monitor.hostname} \
          --auth=trust \
          --skip-pg-hba \
          --ssl-self-signed
      fi

      install -m 0600 ${monitorHba} ${lib.escapeShellArg "${cfg.monitor.dataDir}/qq-bot-ha-pg_hba.conf"}
      install -m 0600 ${monitorPostgresConfig} ${lib.escapeShellArg "${cfg.monitor.dataDir}/qq-bot-ha-local.conf"}

      include="include_if_exists = 'qq-bot-ha-local.conf'"
      if ! grep -Fqx "$include" ${lib.escapeShellArg "${cfg.monitor.dataDir}/postgresql.conf"}; then
        printf '\n%s\n' "$include" >> ${lib.escapeShellArg "${cfg.monitor.dataDir}/postgresql.conf"}
      fi
    '';
  };

  nodePrepare = pkgs.writeShellApplication {
    name = "qq-bot-postgres-node-prepare";
    runtimeInputs = [
      pgAutoFailover
      postgres
      openssl
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.iproute2
    ];
    text = ''
      set -euo pipefail
      umask 0077

      ${waitForAddress cfg.node.hostname}

      if [ ! -f ${lib.escapeShellArg nodeConfigPath} ]; then
        pg_autoctl create postgres \
          --pgdata=${lib.escapeShellArg cfg.node.dataDir} \
          --pgport=${toString cfg.node.port} \
          --pgctl=${postgres}/bin/pg_ctl \
          --pghost=/run/postgresql \
          --listen=${lib.escapeShellArg cfg.node.hostname} \
          --hostname=${lib.escapeShellArg cfg.node.hostname} \
          --name=${lib.escapeShellArg cfg.node.name} \
          --dbname=postgres \
          --monitor=${lib.escapeShellArg monitorUri} \
          --auth=trust \
          --ssl-self-signed \
          --candidate-priority=${toString cfg.node.candidatePriority} \
          --maximum-backup-rate=${lib.escapeShellArg cfg.node.maximumBackupRate}
      fi

      install -m 0600 ${nodeHba} ${lib.escapeShellArg "${cfg.node.dataDir}/qq-bot-ha-access.conf"}
      install -m 0600 ${nodePostgresConfig} ${lib.escapeShellArg "${cfg.node.dataDir}/qq-bot-ha-local.conf"}

      hba=${lib.escapeShellArg "${cfg.node.dataDir}/pg_hba.conf"}
      hba_include="include 'qq-bot-ha-access.conf'"
      if [ "$(head -n 1 "$hba")" != "$hba_include" ]; then
        temporary="$(mktemp "$hba.XXXXXX")"
        printf '%s\n' "$hba_include" > "$temporary"
        grep -Fvx "$hba_include" "$hba" >> "$temporary"
        chmod --reference="$hba" "$temporary"
        mv "$temporary" "$hba"
      fi

      postgres_include="include_if_exists = 'qq-bot-ha-local.conf'"
      if ! grep -Fqx "$postgres_include" ${lib.escapeShellArg "${cfg.node.dataDir}/postgresql.conf"}; then
        printf '\n%s\n' "$postgres_include" >> ${lib.escapeShellArg "${cfg.node.dataDir}/postgresql.conf"}
      fi
    '';
  };

  bootstrapPython = pkgs.python3.withPackages (pythonPackages: [
    pythonPackages.psycopg
  ]);
  bootstrapScript = pkgs.writeText "qq-bot-postgres-bootstrap.py" ''
    import pathlib
    import sys
    import time

    import psycopg
    from psycopg import sql


    password_path = pathlib.Path(sys.argv[1])
    port = int(sys.argv[2])
    password = password_path.read_text(encoding="utf-8").strip()
    if not password:
        raise RuntimeError("qq_bot PostgreSQL password is empty")

    connection = None
    for _ in range(180):
        try:
            connection = psycopg.connect(
                dbname="postgres",
                user="postgres",
                host="/run/postgresql",
                port=port,
                autocommit=True,
                connect_timeout=2,
            )
            break
        except psycopg.OperationalError:
            time.sleep(1)
    if connection is None:
        raise RuntimeError("local PostgreSQL node did not become ready")

    with connection:
        if connection.execute("SELECT pg_is_in_recovery()").fetchone()[0]:
            print("Local node is a standby; application bootstrap is already replicated.")
            raise SystemExit(0)

        role_exists = connection.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = 'qq_bot'"
        ).fetchone()
        operation = "ALTER" if role_exists else "CREATE"
        connection.execute(
            sql.SQL("{} ROLE {} LOGIN PASSWORD {}").format(
                sql.SQL(operation),
                sql.Identifier("qq_bot"),
                sql.Literal(password),
            )
        )
        connection.execute(
            "ALTER ROLE qq_bot NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION LOGIN"
        )

        database_exists = connection.execute(
            "SELECT 1 FROM pg_database WHERE datname = 'qq_bot'"
        ).fetchone()
        if not database_exists:
            connection.execute("CREATE DATABASE qq_bot OWNER qq_bot")
        else:
            connection.execute("ALTER DATABASE qq_bot OWNER TO qq_bot")

    with psycopg.connect(
        dbname="qq_bot",
        user="postgres",
        host="/run/postgresql",
        port=port,
        autocommit=True,
    ) as application_connection:
        application_connection.execute("CREATE EXTENSION IF NOT EXISTS vector")
        application_connection.execute(
            "CREATE SCHEMA IF NOT EXISTS qq_bot AUTHORIZATION qq_bot"
        )
        application_connection.execute(
            "ALTER SCHEMA qq_bot OWNER TO qq_bot"
        )

    print("qq_bot role, database, schema, and pgvector are ready.")
  '';

  backup = pkgs.writeShellApplication {
    name = "qq-bot-postgres-backup";
    runtimeInputs = [
      postgres
      pkgs.coreutils
      pkgs.findutils
    ];
    text = ''
      set -euo pipefail
      umask 0077

      backup_dir=${lib.escapeShellArg cfg.backup.directory}
      data_dir=${lib.escapeShellArg cfg.node.dataDir}
      mkdir -p "$backup_dir"

      if [ -d "$data_dir/log" ]; then
        find "$data_dir/log" -type f -mtime +${toString cfg.logRetentionDays} -delete
      fi
      find "$backup_dir" -type f -name 'qq_bot-*.dump' -mtime +${toString cfg.backup.retentionDays} -delete

      prune_backup_count() {
        find "$backup_dir" -maxdepth 1 -type f -name 'qq_bot-*.dump' -printf '%f\n' \
          | sort --reverse \
          | tail -n +$(( ${toString cfg.backup.retentionCount} + 1 )) \
          | while IFS= read -r old_backup; do
              rm -f -- "$backup_dir/$old_backup"
            done
      }
      prune_backup_count

      recovery="$(psql --host=/run/postgresql --port=${toString cfg.node.port} --username=postgres --dbname=postgres --tuples-only --no-align --command='SELECT pg_is_in_recovery()')"
      if [ "$recovery" = "t" ]; then
        echo "Local node is a standby; skipping the logical backup."
        exit 0
      fi

      database_size="$(psql --host=/run/postgresql --port=${toString cfg.node.port} --username=postgres --dbname=postgres --tuples-only --no-align --command="SELECT pg_database_size('qq_bot')")"
      available="$(df --output=avail --block-size=1 "$backup_dir" | tail -n 1 | tr -d ' ')"
      required=$((database_size * 2 + ${toString cfg.backup.minimumFreeBytes}))
      if [ "$available" -lt "$required" ]; then
        echo "Not enough free space for a verified qq_bot backup while preserving the configured reserve." >&2
        exit 1
      fi

      stamp="$(date -u +%Y%m%dT%H%M%SZ)"
      temporary="$backup_dir/.qq_bot-$stamp.dump.tmp"
      target="$backup_dir/qq_bot-$stamp.dump"
      trap 'rm -f "$temporary"' EXIT

      pg_dump \
        --host=/run/postgresql \
        --port=${toString cfg.node.port} \
        --username=postgres \
        --dbname=qq_bot \
        --format=custom \
        --compress=9 \
        --create \
        --file="$temporary"
      pg_restore --list "$temporary" >/dev/null
      mv "$temporary" "$target"
      trap - EXIT
      prune_backup_count
    '';
  };

  monitorEnvironment = {
    HOME = cfg.monitor.stateDir;
    XDG_CONFIG_HOME = "${cfg.monitor.stateDir}/config";
    XDG_DATA_HOME = "${cfg.monitor.stateDir}/share";
    XDG_RUNTIME_DIR = "/run/qq-bot-postgres-monitor";
  };
  nodeEnvironment = {
    HOME = cfg.node.stateDir;
    XDG_CONFIG_HOME = "${cfg.node.stateDir}/config";
    XDG_DATA_HOME = "${cfg.node.stateDir}/share";
    XDG_RUNTIME_DIR = "/run/qq-bot-postgres-node";
  };

  statusTool = pkgs.writeShellApplication {
    name = "qq-bot-postgres-status";
    runtimeInputs = [pkgs.util-linux];
    text = ''
      set -euo pipefail
      if [ "$EUID" -ne 0 ]; then
        echo "Run this command with sudo." >&2
        exit 1
      fi
      exec runuser -u postgres -- env \
        HOME=${lib.escapeShellArg cfg.monitor.stateDir} \
        XDG_CONFIG_HOME=${lib.escapeShellArg "${cfg.monitor.stateDir}/config"} \
        XDG_DATA_HOME=${lib.escapeShellArg "${cfg.monitor.stateDir}/share"} \
        XDG_RUNTIME_DIR=/run/qq-bot-postgres-monitor \
        PATH=${lib.makeBinPath [pgAutoFailover postgres]} \
        pg_autoctl show state --pgdata ${lib.escapeShellArg cfg.monitor.dataDir}
    '';
  };
  preferPrimaryTool = pkgs.writeShellApplication {
    name = "qq-bot-postgres-prefer-${cfg.preferredNodeName}";
    runtimeInputs = [pkgs.util-linux];
    text = ''
      set -euo pipefail
      if [ "$EUID" -ne 0 ]; then
        echo "Run this command with sudo." >&2
        exit 1
      fi

      run_as_postgres() {
        runuser -u postgres -- env \
          HOME=${lib.escapeShellArg cfg.monitor.stateDir} \
          XDG_CONFIG_HOME=${lib.escapeShellArg "${cfg.monitor.stateDir}/config"} \
          XDG_DATA_HOME=${lib.escapeShellArg "${cfg.monitor.stateDir}/share"} \
          XDG_RUNTIME_DIR=/run/qq-bot-postgres-monitor \
          PATH=${lib.makeBinPath [pgAutoFailover postgres]} \
          "$@"
      }

      primary="$(run_as_postgres psql --host=/run/postgresql --port=${toString cfg.monitor.port} --username=postgres --dbname=pg_auto_failover --tuples-only --no-align --command="SELECT nodename FROM pgautofailover.node WHERE formationid = 'default' AND groupid = 0 AND reportedstate IN ('single', 'wait_primary', 'primary') AND goalstate IN ('single', 'wait_primary', 'primary') LIMIT 1")"
      if [ "$primary" = ${lib.escapeShellArg cfg.preferredNodeName} ]; then
        echo "${cfg.preferredNodeName} is already the writable primary."
        exit 0
      fi

      ready="$(run_as_postgres psql --host=/run/postgresql --port=${toString cfg.monitor.port} --username=postgres --dbname=pg_auto_failover --tuples-only --no-align --command="SELECT count(*) FROM pgautofailover.node WHERE formationid = 'default' AND groupid = 0 AND nodename = '${cfg.preferredNodeName}' AND reportedstate = 'secondary' AND goalstate = 'secondary' AND reportedpgisrunning AND health = 1 AND reporttime > now() - interval '30 seconds'")"
      if [ "$ready" != "1" ]; then
        echo "${cfg.preferredNodeName} is not a healthy synchronized secondary; refusing switchover." >&2
        exit 1
      fi

      run_as_postgres pg_autoctl perform switchover \
        --pgdata ${lib.escapeShellArg cfg.monitor.dataDir} \
        --formation default \
        --group 0 \
        --wait 120
    '';
  };
in {
  options.services.qq-bot-postgres-ha = {
    enable = mkEnableOption "the dedicated highly available QQ bot PostgreSQL cluster";
    passwordFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "File containing the qq_bot application role password.";
    };
    applicationClientCidr = mkOption {
      type = types.str;
      default = "100.64.0.3/32";
      description = "Exact Tailscale source CIDR allowed to use the qq_bot role.";
    };
    peerAddresses = mkOption {
      type = types.listOf types.str;
      default = ["100.64.0.3" "100.64.0.4"];
      description = "Exact Tailscale addresses allowed to contact the monitor.";
    };
    preferredNodeName = mkOption {
      type = types.strMatching "[A-Za-z0-9_-]+";
      default = "tank";
      description = "Node selected by the guarded manual failback command.";
    };
    logRetentionDays = mkOption {
      type = types.ints.positive;
      default = 7;
      description = "Number of days to keep PostgreSQL collector logs.";
    };

    monitor = {
      enable = mkEnableOption "the pg_auto_failover monitor";
      hostname = mkOption {
        type = types.str;
        default = "100.64.0.3";
      };
      port = mkOption {
        type = types.port;
        default = 55431;
      };
      stateDir = mkOption {
        type = types.str;
        default = "/var/lib/qq-bot-postgres-monitor";
      };
      dataDir = mkOption {
        type = types.str;
        default = "/var/lib/qq-bot-postgres-monitor/data";
      };
    };

    node = {
      enable = mkEnableOption "a pg_auto_failover PostgreSQL keeper";
      name = mkOption {
        type = types.strMatching "[A-Za-z0-9_-]+";
      };
      hostname = mkOption {
        type = types.str;
      };
      port = mkOption {
        type = types.port;
        default = 55432;
      };
      stateDir = mkOption {
        type = types.str;
      };
      dataDir = mkOption {
        type = types.str;
      };
      candidatePriority = mkOption {
        type = types.ints.between 0 100;
        default = 50;
      };
      maximumBackupRate = mkOption {
        type = types.str;
        default = "100M";
      };
      walKeepSize = mkOption {
        type = types.str;
        default = "1GB";
      };
      maxSlotWalKeepSize = mkOption {
        type = types.str;
        default = "16GB";
      };
      maxWalSize = mkOption {
        type = types.str;
        default = "4GB";
      };
      minWalSize = mkOption {
        type = types.str;
        default = "1GB";
      };
    };

    backup = {
      enable = mkOption {
        type = types.bool;
        default = true;
      };
      directory = mkOption {
        type = types.str;
      };
      retentionDays = mkOption {
        type = types.ints.positive;
        default = 7;
      };
      retentionCount = mkOption {
        type = types.ints.positive;
        default = 7;
        description = "Maximum number of verified logical backups retained locally.";
      };
      minimumFreeBytes = mkOption {
        type = types.ints.positive;
        default = 20 * 1024 * 1024 * 1024;
      };
      onCalendar = mkOption {
        type = types.str;
        default = "*-*-* 03:20:00";
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.monitor.enable || cfg.node.enable;
        message = "qq-bot-postgres-ha must enable a monitor, a node, or both";
      }
      {
        assertion = !cfg.node.enable || cfg.passwordFile != null;
        message = "qq-bot-postgres-ha.passwordFile is required on data nodes";
      }
    ];

    users = mkIf (!config.services.postgresql.enable) {
      groups.postgres.gid = config.ids.gids.postgres;
      users.postgres = {
        uid = config.ids.uids.postgres;
        group = "postgres";
        isSystemUser = true;
        home = "/var/lib/postgresql";
        createHome = true;
      };
    };

    systemd.tmpfiles.rules =
      [
        "d /run/postgresql 0755 postgres postgres -"
      ]
      ++ lib.optionals cfg.monitor.enable [
        "d ${cfg.monitor.stateDir} 0700 postgres postgres -"
        "d ${cfg.monitor.stateDir}/config 0700 postgres postgres -"
        "d ${cfg.monitor.stateDir}/share 0700 postgres postgres -"
        "d ${builtins.dirOf cfg.monitor.dataDir} 0700 postgres postgres -"
      ]
      ++ lib.optionals cfg.node.enable [
        "d ${cfg.node.stateDir} 0700 postgres postgres -"
        "d ${cfg.node.stateDir}/config 0700 postgres postgres -"
        "d ${cfg.node.stateDir}/share 0700 postgres postgres -"
        "d ${builtins.dirOf cfg.node.dataDir} 0700 postgres postgres -"
      ]
      ++ lib.optionals (cfg.node.enable && cfg.backup.enable) [
        "d ${cfg.backup.directory} 0700 postgres postgres -"
      ];

    systemd.services.qq-bot-postgres-monitor = mkIf cfg.monitor.enable {
      description = "QQ bot PostgreSQL HA monitor";
      wantedBy = ["multi-user.target"];
      after = ["network-online.target" "tailscaled.service"];
      wants = ["network-online.target" "tailscaled.service"];
      startLimitIntervalSec = 0;
      path = [pgAutoFailover postgres openssl pkgs.coreutils pkgs.gnugrep pkgs.iproute2];
      environment = monitorEnvironment;
      preStart = lib.getExe monitorPrepare;
      serviceConfig = {
        Type = "simple";
        User = "postgres";
        Group = "postgres";
        RuntimeDirectory = "qq-bot-postgres-monitor";
        RuntimeDirectoryMode = "0700";
        ExecStart = "${pgAutoFailover}/bin/pg_autoctl run --pgdata ${cfg.monitor.dataDir}";
        Restart = "always";
        RestartSec = "5s";
        TimeoutStartSec = "10min";
        TimeoutStopSec = "2min";
        KillMode = "mixed";
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        ReadWritePaths = [cfg.monitor.stateDir "/run/postgresql"];
        RestrictAddressFamilies = ["AF_UNIX" "AF_INET" "AF_INET6"];
        LockPersonality = true;
      };
    };

    systemd.services.qq-bot-postgres-node = mkIf cfg.node.enable {
      description = "QQ bot PostgreSQL HA data node (${cfg.node.name})";
      wantedBy = ["multi-user.target"];
      after =
        ["network-online.target" "tailscaled.service"]
        ++ lib.optionals cfg.monitor.enable ["qq-bot-postgres-monitor.service"];
      wants =
        ["network-online.target" "tailscaled.service"]
        ++ lib.optionals cfg.monitor.enable ["qq-bot-postgres-monitor.service"];
      startLimitIntervalSec = 0;
      path = [pgAutoFailover postgres openssl pkgs.coreutils pkgs.gnugrep pkgs.iproute2];
      environment = nodeEnvironment;
      preStart = lib.getExe nodePrepare;
      serviceConfig = {
        Type = "simple";
        User = "postgres";
        Group = "postgres";
        RuntimeDirectory = "qq-bot-postgres-node";
        RuntimeDirectoryMode = "0700";
        ExecStart = "${pgAutoFailover}/bin/pg_autoctl run --pgdata ${cfg.node.dataDir}";
        Restart = "always";
        RestartSec = "5s";
        TimeoutStartSec = "1h";
        TimeoutStopSec = "5min";
        KillMode = "mixed";
        LimitNOFILE = 65536;
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        ReadWritePaths = [cfg.node.stateDir (builtins.dirOf cfg.node.dataDir) "/run/postgresql"];
        RestrictAddressFamilies = ["AF_UNIX" "AF_INET" "AF_INET6"];
        LockPersonality = true;
      };
    };

    systemd.services.qq-bot-postgres-bootstrap = mkIf cfg.node.enable {
      description = "Create the QQ bot PostgreSQL role, database, schema, and extensions";
      wantedBy = ["multi-user.target"];
      after = ["qq-bot-postgres-node.service" "sops-install-secrets.service"];
      requires = ["qq-bot-postgres-node.service"];
      serviceConfig = {
        Type = "oneshot";
        User = "postgres";
        Group = "postgres";
        RemainAfterExit = true;
        ExecStart = "${bootstrapPython}/bin/python ${bootstrapScript} ${passwordFile} ${toString cfg.node.port}";
        TimeoutStartSec = "5min";
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateNetwork = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        RestrictAddressFamilies = ["AF_UNIX"];
      };
    };

    systemd.services.qq-bot-postgres-backup = mkIf (cfg.node.enable && cfg.backup.enable) {
      description = "Capacity-aware verified backup of the QQ bot PostgreSQL database";
      after = ["qq-bot-postgres-node.service"];
      requires = ["qq-bot-postgres-node.service"];
      serviceConfig = {
        Type = "oneshot";
        User = "postgres";
        Group = "postgres";
        ExecStart = lib.getExe backup;
        TimeoutStartSec = "2h";
        UMask = "0077";
        NoNewPrivileges = true;
        PrivateNetwork = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [cfg.backup.directory "-${cfg.node.dataDir}/log"];
        RestrictAddressFamilies = ["AF_UNIX"];
      };
    };
    systemd.timers.qq-bot-postgres-backup = mkIf (cfg.node.enable && cfg.backup.enable) {
      description = "Daily QQ bot PostgreSQL backup timer";
      wantedBy = ["timers.target"];
      timerConfig = {
        OnCalendar = cfg.backup.onCalendar;
        Persistent = true;
        RandomizedDelaySec = "10m";
        Unit = "qq-bot-postgres-backup.service";
      };
    };

    environment.systemPackages = lib.optionals cfg.monitor.enable [
      statusTool
      preferPrimaryTool
    ];
  };
}
