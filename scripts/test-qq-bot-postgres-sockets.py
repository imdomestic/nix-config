"""Verify socket-directory isolation with disposable, Unix-only PostgreSQLs."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-bin", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise SystemExit("Run as an unprivileged user, never postgres or root.")
    if os.environ.get("USER") == "postgres":
        raise SystemExit("Use a non-production account for this check.")

    env = {key: value for key, value in os.environ.items() if not key.startswith("PG")}

    def run(tool: str, *arguments: str) -> str:
        result = subprocess.run(
            [str(args.postgres_bin / tool), *arguments],
            env=env,
            capture_output=True,
            text=True,
            timeout=40,
        )
        if result.returncode:
            raise RuntimeError(f"{tool}: {result.stderr.strip()}")
        return result.stdout.strip()

    # Keep paths short enough for Unix sockets, including on macOS.
    with tempfile.TemporaryDirectory(prefix="pgsock-", dir="/tmp") as directory:
        root = Path(directory)
        instances = {}
        running = []
        try:
            for name in ("unrelated", "monitor", "node"):
                data = root / (name + "-data")
                socket = root / (name + "-socket")
                socket.mkdir(mode=0o700)
                run("initdb", "-D", str(data), "--no-locale", "-A", "trust", "-U", "tester")
                options = (
                    f"-k {socket} -p 55439 -c listen_addresses='' "
                    "-c shared_buffers=16MB -c max_connections=10 -c fsync=off"
                )
                instances[name] = (data, socket, options)
                running.append(name)
                run("pg_ctl", "-D", str(data), "-l", str(root / (name + ".log")), "-o", options, "-w", "start")

            def query(name: str, sql: str) -> str:
                _, socket, _ = instances[name]
                return run("psql", "-XAt", "-h", str(socket), "-p", "55439", "-U", "tester", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", sql)

            for name in ("monitor", "node"):
                query(name, "CREATE TABLE socket_check (value text)")
                query(name, "INSERT INTO socket_check VALUES ('preserved')")

            shared_data, shared_socket, shared_options = instances["unrelated"]
            run("pg_ctl", "-D", str(shared_data), "-m", "fast", "-w", "stop")
            running.remove("unrelated")
            shutil.rmtree(shared_socket)
            shared_socket.mkdir(mode=0o700)
            running.append("unrelated")
            run("pg_ctl", "-D", str(shared_data), "-l", str(root / "unrelated.log"), "-o", shared_options, "-w", "start")

            for name in ("monitor", "node"):
                if query(name, "SELECT value FROM socket_check") != "preserved":
                    raise AssertionError(f"{name} lost its connection or data")
                if query(name, "SHOW unix_socket_directories") != str(instances[name][1]):
                    raise AssertionError(f"{name} is not using its own socket directory")
            print("PASS: unrelated PostgreSQL restart/directory cleanup leaves both HA sockets usable")
        finally:
            failures = []
            for name in reversed(running):
                try:
                    data = instances[name][0]
                    if (data / "postmaster.pid").exists():
                        run("pg_ctl", "-D", str(data), "-m", "immediate", "-w", "stop")
                except Exception as exc:
                    failures.append(f"{name}: {exc}")
            if failures:
                raise RuntimeError("Temporary PostgreSQL cleanup failed: " + "; ".join(failures))


if __name__ == "__main__":
    main()
