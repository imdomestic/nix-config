# Run only before startup, with PostgreSQL tools on PATH. Never change roles.
set -euo pipefail

data=${1:?PGDATA required}
role=${2:?primary or standby required}
if [ ! -f "$data/PG_VERSION" ] || [ "$(tr -d '\r\n' < "$data/PG_VERSION")" != 17 ]; then
  echo "An existing PostgreSQL 17 data directory is required; refusing initialization." >&2
  exit 1
fi
if pg_ctl -D "$data" status >/dev/null 2>&1; then
  echo "PostgreSQL is still running; refusing uncoordinated startup." >&2
  exit 1
fi
if [ -f "$data/recovery.signal" ]; then
  echo "Archive recovery requires a separate operator procedure." >&2
  exit 1
fi
case "$role" in
  primary)
    state="$(LC_ALL=C pg_controldata "$data")"
    if [ -f "$data/standby.signal" ] || printf '%s\n' "$state" | grep -Eq 'Database cluster state:.*(shut down in recovery|in archive recovery)'; then
      echo "Configured primary is still a standby; refusing implicit promotion." >&2
      exit 1
    fi
    ;;
  standby)
    if [ ! -f "$data/standby.signal" ]; then
      echo "Configured standby lacks standby.signal; refusing writable startup." >&2
      exit 1
    fi
    ;;
  *) echo "Unknown fixed role." >&2; exit 2 ;;
esac
