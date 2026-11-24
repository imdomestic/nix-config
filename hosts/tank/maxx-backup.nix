# maxx's database, backed up every night to h610 by restic: a pg_dump of
# it, which restic cuts into chunks and keeps once each, compressed and
# encrypted, so that a night adds about what changed. Once a week the
# latest is restored into a scratch cluster and looked at. Restoring, and
# a backup before a deploy: docs/runbooks/maxx-backup.md.
{
  config,
  inputs,
  pkgs,
  ...
}: let
  pg = config.services.maxx.postgresql.package;
  # tank's root is h610's root through Tailscale SSH, with no key; a user
  # of its own on h610 would hold nothing back. tailscaled shows h610's
  # /etc/ssh/ssh_host_ed25519_key.
  knownHosts = pkgs.writeText "h610-known-hosts" ''
    h610.inner.imdomestic.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH76Na3Lc8mPT2wjG/su5xRaE7OptqY1nlVoRf+yDRPy
  '';
  sftp = "ssh -o BatchMode=yes -o UserKnownHostsFile=${knownHosts} root@h610.inner.imdomestic.com -s sftp";
  repository = "sftp:root@h610.inner.imdomestic.com:/var/lib/restic/tank-maxx";
  password = config.sops.secrets."maxx/restic-password".path;

  # The latest backup in a cluster of its own, made as maxx's is, on a
  # socket in a private /var/tmp: it restores whole, has a turn's
  # migrations and messages from the last two days.
  restoreCheck = pkgs.writeShellApplication {
    name = "maxx-restore-check";
    runtimeInputs = [pg pkgs.restic pkgs.openssh pkgs.util-linux pkgs.coreutils];
    text = ''
      work=$(mktemp -d /var/tmp/maxx-restore-check.XXXXXX)
      chown maxx-postgres: "$work"
      as() { runuser -u maxx-postgres -- "$@"; }
      cleanup() {
        as pg_ctl --pgdata="$work/data" --mode=immediate stop > /dev/null 2>&1 || true
        rm -rf -- "$work"
      }
      trap cleanup EXIT
      as initdb --pgdata="$work/data" --username=maxx-postgres --auth-local=trust \
        --auth-host=reject ${pkgs.lib.escapeShellArgs (import "${inputs.maxx}/nix/initdb.nix")} > /dev/null
      as pg_ctl --pgdata="$work/data" --wait --silent --log="$work/postgres.log" \
        --options="-c listen_addresses= -k $work -c fsync=off -c synchronous_commit=off -c full_page_writes=off" start
      sql() {
        as psql --host="$work" --dbname="$1" --no-psqlrc --quiet --tuples-only --no-align \
          --set=ON_ERROR_STOP=1 "''${@:2}"
      }
      sql postgres --command="create role maxx" --command="create database maxx owner maxx"
      restic -o sftp.command="${sftp}" --retry-lock=30m dump latest /maxx.sql | sql maxx > /dev/null
      migrations=$(sql maxx --command="select count(*) from _sqlx_migrations where success")
      messages=$(sql maxx --command="select count(*) from messages")
      hours=$(sql maxx --command="select extract(epoch from now() - max(received_at))::bigint / 3600 from messages")
      echo "restored: $migrations migrations, $messages messages, the newest $hours h old"
      if [ "$migrations" -eq 0 ] || [ "$hours" -gt 48 ]; then
        echo "the latest backup is empty or stale" >&2
        exit 1
      fi
    '';
  };
in {
  sops.secrets."maxx/restic-password".sopsFile = ../../secrets/hosts/tank-max.yaml;

  services.restic.backups.maxx = {
    inherit repository;
    passwordFile = password;
    initialize = true;
    extraOptions = ["sftp.command='${sftp}'"];
    # As the cluster's superuser, on its socket; a dump that fails fails
    # the backup, rather than keep what it wrote.
    command = [
      "${pkgs.util-linux}/bin/runuser"
      "-u"
      "maxx-postgres"
      "--"
      "${pg}/bin/pg_dump"
      "--host=/run/maxx-postgres"
      "--dbname=maxx"
    ];
    extraBackupArgs = ["--stdin-filename=maxx.sql" "--tag=maxx"];
    pruneOpts = ["--keep-daily 14" "--keep-weekly 8" "--keep-monthly 12"];
    runCheck = true;
    timerConfig = {
      OnCalendar = "*-*-* 04:20:00";
      Persistent = true;
    };
  };

  systemd.services.maxx-restore-check = {
    description = "Restore maxx's latest backup into a scratch cluster and look at it";
    wants = ["network-online.target"];
    after = ["network-online.target"];
    environment = {
      RESTIC_REPOSITORY = repository;
      RESTIC_PASSWORD_FILE = password;
      RESTIC_CACHE_DIR = "/var/cache/maxx-restore-check";
    };
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${restoreCheck}/bin/maxx-restore-check";
      CacheDirectory = "maxx-restore-check";
      CacheDirectoryMode = "0700";
      PrivateTmp = true;
      TimeoutStartSec = "1h";
    };
  };
  systemd.timers.maxx-restore-check = {
    wantedBy = ["timers.target"];
    timerConfig = {
      OnCalendar = "Sun *-*-* 05:50:00";
      Persistent = true;
    };
  };
}
