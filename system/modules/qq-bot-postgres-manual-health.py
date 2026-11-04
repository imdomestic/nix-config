"""Read-only fixed-role replication health; never promote, fence or restart."""
import datetime as dt
import json
import os
from pathlib import Path
import sys

import psycopg


def inspect(connection, *, role, slot, maximum_lag, primary_host):
    recovering = connection.execute("SELECT pg_is_in_recovery()").fetchone()[0]
    result = {"in_recovery": recovering, "expected_role": role}
    if recovering != (role == "standby"):
        return {**result, "status": "unhealthy", "reason": "unexpected local database role"}
    if recovering:
        row = connection.execute("""SELECT status, sender_host,
            GREATEST(0, EXTRACT(EPOCH FROM clock_timestamp()-last_msg_receipt_time)),
            pg_wal_lsn_diff(latest_end_lsn, pg_last_wal_replay_lsn())
            FROM pg_stat_wal_receiver""").fetchone()
        connected = row is not None and row[0] == "streaming" and row[1] == primary_host
        configured_slot = connection.execute("SHOW primary_slot_name").fetchone()[0]
        connected = connected and configured_slot == slot
    else:
        row = connection.execute("""SELECT state, application_name,
            GREATEST(0, EXTRACT(EPOCH FROM clock_timestamp()-reply_time)),
            pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)
            FROM pg_stat_replication WHERE application_name = %s""", (slot,)).fetchone()
        connected = row is not None and row[0] == "streaming"
        physical_slot = connection.execute("""SELECT active FROM pg_replication_slots
            WHERE slot_name = %s AND slot_type = 'physical'""", (slot,)).fetchone()
        connected = connected and physical_slot is not None and physical_slot[0]
    age = float(row[2]) if row is not None and row[2] is not None else None
    lag = max(0, int(row[3])) if row is not None and row[3] is not None else None
    healthy = connected and age is not None and age <= 300 and lag is not None and lag <= maximum_lag
    return {**result, "replication_connected": bool(connected), "replication_age_seconds": age,
            "replication_lag_bytes": lag, "status": "healthy" if healthy else "unhealthy",
            "reason": "fixed role and asynchronous replication verified" if healthy
                      else "replication unavailable, stale or above lag budget; local role unchanged"}


def main():
    node, port, socket, output, role, slot, maximum_lag, primary_host = sys.argv[1:]
    result = {"checked_at": dt.datetime.now(dt.timezone.utc).isoformat(), "node": node, "mode": "manual"}
    try:
        with psycopg.connect(dbname="postgres", user="postgres", host=socket, port=int(port),
                             connect_timeout=2, options="-c statement_timeout=2000 -c default_transaction_read_only=on") as connection:
            result.update(inspect(connection, role=role, slot=slot,
                                  maximum_lag=int(maximum_lag), primary_host=primary_host))
    except Exception as error:
        result.update(status="unhealthy", reason=f"local database check failed: {type(error).__name__}")
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, target)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "healthy" else 1


if __name__ == "__main__":
    raise SystemExit(main())
