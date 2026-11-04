"""Disposable fixed-role replication drill; run unprivileged in a private network."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import time

import psycopg


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-bin", type=Path, required=True)
    parser.add_argument("--role-check", type=Path, required=True)
    parser.add_argument("--health-module", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0 or os.environ.get("USER") == "postgres":
        raise SystemExit("Use an isolated, unprivileged test user, not the production postgres account.")
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
    env["PATH"] = str(args.postgres_bin) + ":" + env.get("PATH", "")
    spec = importlib.util.spec_from_file_location("health", args.health_module)
    health = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(health)

    def run(tool, *params):
        result = subprocess.run([str(args.postgres_bin / tool), *map(str, params)],
                                env=env, capture_output=True, text=True, timeout=40)
        if result.returncode:
            raise RuntimeError(f"{tool}: {result.stderr}")
        return result.stdout.strip()

    def guard(data, role, allowed):
        result = subprocess.run(["bash", str(args.role_check), str(data), role], env=env,
                                capture_output=True, text=True, timeout=10)
        assert (result.returncode == 0) == allowed, result.stderr

    with tempfile.TemporaryDirectory(prefix="qqfixed-", dir="/tmp") as directory:
        root = Path(directory)
        primary, standby = root / "primary", root / "standby"
        sockets = [root / "p-socket", root / "s-socket"]
        for socket in sockets:
            socket.mkdir()
        run("initdb", "-D", primary, "-A", "trust", "--no-locale", "--encoding=UTF8", "-U", "tester")
        with (primary / "postgresql.conf").open("a") as stream:
            stream.write("\nwal_level=replica\nmax_wal_senders=3\nmax_replication_slots=3\nwal_sender_timeout='2s'\n")
        port = 55439

        def query(which, sql, values=None):
            with psycopg.connect(host=str(sockets[which]), port=port + which,
                                 user="tester", dbname="postgres", autocommit=True) as c:
                cursor = c.execute(sql, values)
                return cursor.fetchall() if cursor.description is not None else []

        def check(which):
            with psycopg.connect(host=str(sockets[which]), port=port + which,
                                 user="tester", dbname="postgres", autocommit=True) as c:
                return health.inspect(c, role="primary" if which == 0 else "standby",
                                      slot="qq_bot_standby", maximum_lag=1024 * 1024, primary_host="127.0.0.1")

        def start(which):
            data = (primary, standby)[which]
            options = (f"-k {sockets[which]} -p {port + which} -c listen_addresses=127.0.0.1 "
                       "-c shared_buffers=16MB -c synchronous_standby_names='' ")
            if which:
                options += (f"-c primary_conninfo='host=127.0.0.1 port={port} user=tester "
                            "application_name=qq_bot_standby connect_timeout=2' -c primary_slot_name=qq_bot_standby")
            run("pg_ctl", "-D", data, "-l", root / f"{which}.log", "-o", options, "-w", "start")

        def until(predicate):
            deadline = time.monotonic() + 15
            while not predicate():
                if time.monotonic() > deadline:
                    raise AssertionError(f"Replica did not converge: primary={check(0)}, standby={check(1)}")
                time.sleep(0.1)

        try:
            guard(primary, "primary", True)
            guard(primary, "standby", False)
            start(0)
            guard(primary, "primary", False)
            query(0, "SELECT pg_create_physical_replication_slot('qq_bot_standby')")
            query(0, "CREATE TABLE recovery_test (n integer)")
            run("pg_basebackup", "-h", "127.0.0.1", "-p", port, "-U", "tester", "-D", standby, "-X", "stream", "-R")
            guard(standby, "standby", True)
            guard(standby, "primary", False)
            start(1)
            query(0, "INSERT INTO recovery_test VALUES (1)")
            until(lambda: check(0)["status"] == check(1)["status"] == "healthy")
            until(lambda: query(1, "SELECT count(*) FROM recovery_test")[0][0] == 1)
            print("PASS: fixed primary/standby stream and read-only health agrees", flush=True)

            hba = primary / "pg_hba.conf"
            original = hba.read_text()
            hba.write_text("host replication all 127.0.0.1/32 reject\n" + original)
            query(0, "SELECT pg_reload_conf()")
            query(0, "SELECT pg_terminate_backend(pid) FROM pg_stat_replication")
            for _ in range(25):
                query(0, "INSERT INTO recovery_test VALUES (2)")
                assert query(0, "SELECT pg_is_in_recovery()")[0][0] is False
                assert query(1, "SELECT pg_is_in_recovery()")[0][0] is True
                time.sleep(1)
            assert check(0)["status"] == check(1)["status"] == "unhealthy"
            print("PASS: 25s replication outage leaves primary writable and standby read-only; health alerts", flush=True)
            hba.write_text(original)
            query(0, "SELECT pg_reload_conf()")
            until(lambda: query(1, "SELECT count(*) FROM recovery_test")[0][0] == 26)
            until(lambda: check(0)["status"] == check(1)["status"] == "healthy")
            print("PASS: replication reconnects and catches up without promotion", flush=True)

            run("pg_ctl", "-D", primary, "-m", "fast", "-w", "stop")
            for _ in range(25):
                assert query(1, "SELECT pg_is_in_recovery()")[0][0] is True
                time.sleep(1)
            print("PASS: primary shutdown beyond the old partition timeout never promotes standby", flush=True)
            run("pg_ctl", "-D", standby, "-m", "fast", "-w", "stop")
            (standby / "standby.signal").unlink()
            guard(standby, "standby", False)
            guard(standby, "primary", False)
            (standby / "standby.signal").touch()
            guard(standby, "standby", True)
            guard(primary, "primary", True)
            start(0)
            start(1)
            until(lambda: check(0)["status"] == check(1)["status"] == "healthy")
            print("PASS: role guards reject missing signal/implicit promotion; restarts preserve roles and data", flush=True)
        finally:
            for data in (standby, primary):
                if (data / "postmaster.pid").exists():
                    run("pg_ctl", "-D", data, "-m", "immediate", "-w", "stop")


if __name__ == "__main__":
    main()
