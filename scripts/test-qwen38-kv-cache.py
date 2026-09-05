#!/usr/bin/env python3
"""Exercise Host KV restoration and full-catalog admission on a quiescent backend."""

import argparse
import datetime
import json
from pathlib import Path
import shlex
import subprocess
import time
import urllib.request
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:18101")
    parser.add_argument("--ssh-target", default="hank@b650")
    parser.add_argument("--log", default="/var/lib/qwen38/ninfer-logs/qwen38-long.jsonl")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    def read_log():
        command = "sudo -n tail -n 6000 -- " + shlex.quote(args.log)
        result = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", args.ssh_target, command],
            check=True, capture_output=True, text=True, timeout=30,
        )
        return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]

    initial = read_log()
    start = next(row for row in reversed(initial) if row["event"] == "server_start")
    instance = start["server_instance_id"]
    cache = start["engine"]["context_cache"]
    if cache["max_private_continuations"] != 8:
        raise RuntimeError("This regression scenario requires exactly eight private owners")
    if start["engine"]["kv_capacity"] != 262144:
        raise RuntimeError("This regression scenario requires the 262144-token device pool")
    if any(row["event"] == "request_start" and row["server_instance_id"] == instance
           for row in initial):
        raise RuntimeError("Start with a fresh backend and pause other clients before testing")

    run_id = uuid.uuid4().hex
    started_ms = int(time.time() * 1000)
    requests = []
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def send(phase, session):
        # The unique identity precedes the large suffix, so these are independent KV histories.
        prompt = f"KV regression {run_id}, independent conversation {session}.\n"
        prompt += " alpha" * 45000
        prompt += "\nReply with OK."
        body = json.dumps({
            "model": "qwen3.8-27b",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 8,
            "temperature": 0,
            "stream": False,
        }).encode()
        request = urllib.request.Request(
            args.url.rstrip("/") + "/v1/chat/completions", data=body,
            headers={"Content-Type": "application/json"},
        )
        began = time.monotonic()
        with opener.open(request, timeout=300) as response:
            reply = json.load(response)
        elapsed = time.monotonic() - began
        record = {"phase": phase, "session": session, "wall_seconds": elapsed,
                  "usage": reply.get("usage", {})}
        requests.append(record)
        print(json.dumps(record), flush=True)

    for phase in ("cold", "warm"):
        for session in range(1, 8):
            send(phase, session)
    send("fill_eighth_slot", 8)
    send("full_catalog_admission", 9)
    send("retained_owner_probe", 7)
    time.sleep(6)  # Throughput transfer counters are interval deltas, published every five seconds.

    rows = [row for row in read_log()
            if row["server_instance_id"] == instance and row["timestamp_unix_ms"] >= started_ms]
    completed = [row for row in rows if row["event"] == "request_done"]
    if len(completed) != len(requests):
        raise RuntimeError(f"Expected {len(requests)} completions, observed {len(completed)}")
    for request, row in zip(requests, completed):
        request.update(request_id=row["request"]["request_id"], result=row["result"],
                       materialization=row["materialization"], timings_seconds=row["timings_seconds"])

    intervals = [row["context_cache"] for row in rows if row["event"] == "throughput"]
    transfers = {
        kind: {direction: {
            key: sum(row[kind][direction][key] for row in intervals)
            for key in ("bytes", "pages", "seconds")
        } for direction in ("d2h", "h2d")}
        for kind in ("main_kv_transfers", "backend_kv_transfers")
    }
    evictions = sum(row["pressure"]["private_owners_evicted"] for row in intervals)
    fallbacks = sum(row["materialization"]["selected_maximal_fallback"] for row in completed)
    cold = [row for row in requests if row["phase"] == "cold"]
    warm = [row for row in requests if row["phase"] == "warm"]
    errors = []
    if sum(row["result"]["prompt_tokens"] for row in cold) <= 262144:
        errors.append("Workload did not exceed device KV capacity")
    if any(row["result"]["prefix_cache_hit_tokens"] for row in cold):
        errors.append("Cold requests unexpectedly shared a prefix")
    if any(row["result"]["prefix_cache_hit_tokens"] < row["result"]["prompt_tokens"] * 0.99
           for row in warm):
        errors.append("At least one retained conversation lost its full-prompt cache hit")
    if not all(transfers["main_kv_transfers"][direction]["bytes"] > 0 for direction in ("d2h", "h2d")):
        errors.append("Both Main KV spill and restore must occur")
    if evictions != 1:
        errors.append(f"Ninth independent owner should evict one private owner, observed {evictions}")
    if fallbacks:
        errors.append(f"Unexpected maximal fallback selections: {fallbacks}")
    if requests[-1]["result"]["prefix_cache_hit_tokens"] == 0:
        errors.append("Recently reused owner disappeared after full-catalog admission")
    report = {
        "run_id": run_id, "completed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "server_instance_id": instance, "engine": start["engine"], "requests": requests,
        "transfers": transfers, "private_owners_evicted": evictions, "maximal_fallbacks": fallbacks,
        "peak_host_kv_bytes": max(row["occupancy"]["host_kv_bytes"] for row in intervals),
        "peak_host_state_slots": max(row["occupancy"]["host_state_slots"] for row in intervals),
        "errors": errors, "passed": not errors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "requests"}), flush=True)
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
