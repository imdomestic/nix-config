#!/usr/bin/env python3
"""Read-only live acceptance; never print credentials, journals or alert bodies."""

import argparse
import json
from pathlib import Path
import sys
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hub-url", required=True)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path, help="JSON array from services.maxops-hub.hosts")
    args = parser.parse_args()
    token = args.token_file.read_text().strip()
    inventory = json.loads(args.inventory.read_text())
    expected_hosts = {host["name"] for host in inventory}
    assert expected_hosts and len(expected_hosts) == len(inventory)
    opener = build_opener(ProxyHandler({}), NoRedirect())

    def request(path, payload=None, credential=token, expected=200):
        headers = {"Content-Type": "application/json"}
        if credential is not None:
            headers["Authorization"] = "Bearer " + credential
        body = None if payload is None else json.dumps(payload).encode()
        try:
            with opener.open(Request(args.hub_url.rstrip("/") + path, data=body, headers=headers), timeout=30) as response:
                status, body = response.status, response.read(2 * 1024 * 1024 + 1)
        except HTTPError as error:
            status, body = error.code, error.read(4096)
        context = path if payload is None else payload["op"] + " " + str(payload.get("params", {}).get("host", "fleet"))
        assert status == expected, f"{context}: expected HTTP {expected}, got {status}"
        assert len(body) <= 2 * 1024 * 1024
        return json.loads(body) if expected == 200 else None

    def query(operation, params=None, expected=200):
        return request("/v1/execute", {"op": operation, "params": params or {}}, expected=expected)

    catalog = request("/v1/operations?view=tools")
    assert catalog["version"] == 2
    assert catalog["next_cursor"] is None
    operations = {operation["name"]: operation for operation in catalog["operations"]}
    assert {"fleet.overview", "host.facts", "host.metrics", "deploy.status", "units.list",
            "units.failed", "units.status", "units.logs", "alerts.active", "resources.list",
            "jobs.wait", "jobs.events", "jobs.result", "deploy.run", "events.recent", "events.get"} <= set(operations)
    assert all("params_schema" in operation and "response_schema" not in operation for operation in operations.values())
    summary = request("/v1/operations?view=summary&limit=2")
    assert len(summary["operations"]) == 2 and summary["next_cursor"]
    assert all("params_schema" not in entry and "response_schema" not in entry for entry in summary["operations"])
    discovered = query("resources.list", {"kind": "hosts", "limit": 200})
    assert {entry["host"] for entry in discovered["resources"]} == expected_hosts
    assert discovered["next_cursor"] is None
    overview = query("fleet.overview")
    assert {host["host"] for host in overview["hosts"]} == expected_hosts
    deployments = query("deploy.status")
    assert {host["host"] for host in deployments["hosts"]} == expected_hosts
    for entry in overview["hosts"]:
        assert entry["agent"]["state"] == "reachable", f"{entry['host']}: agent unavailable"
        assert entry["exporter"]["state"] == "up", f"{entry['host']}: exporter is not freshly up"
    restart_history = []
    for host in inventory:
        name = host["name"]
        params = {"host": name}
        facts = query("host.facts", params)
        assert facts["host"] == name and facts["facts"]["system_closure"]
        deployment = next(entry for entry in deployments["hosts"] if entry["host"] == name)
        assert deployment["state"] == "available" and deployment["activated_at"] is None
        assert deployment["running_closure"] == facts["facts"]["system_closure"]
        assert deployment["profile_matches_running"] is True, f"{name}: running/profile mismatch"
        units = query("units.list", dict(params, limit=200))
        coverage = "all_loaded" if host.get("readAllUnits", False) else "allowlist"
        assert units["unit_scope"]["coverage"] == coverage
        names = {unit["unit"] for unit in units["units"]}
        # Name-filtered pages avoid a busy host's unrelated transient unit churn.
        for unit in host["readableUnits"]:
            page = query("units.list", dict(params, prefix=unit))
            assert unit in {entry["unit"] for entry in page["units"]}
        if host.get("readAllUnits", False):
            assert units["total"] >= len(host["readableUnits"])
            query("units.status", dict(params, unit="multi-user.target"))
            unknown = query("units.status", dict(params, unit="maxops-unloaded-fixture.service"))
            assert unknown["unit"]["load_state"] == "not-loaded"
            assert unknown["unit"]["active_state"] == "unknown"
        else:
            assert names == set(host["readableUnits"])
        status = query("units.status", {"host": name, "unit": "maxops-agent.service"})
        assert status["unit"]["active_state"] == "active"
        assert status["unit"]["details"]["main_pid"] > 0
        restarts = status["unit"]["details"]["restarts"]
        if restarts != 0:
            restart_history.append(f"{name}: {restarts} agent restarts")
        logs = query("units.logs", {"host": name, "unit": "maxops-agent.service", "lines": 10, "since_seconds": 3600})
        assert len(logs["entries"]) <= 10
        assert all(set(entry) == {"timestamp_us", "priority", "message"} for entry in logs["entries"])
        metrics = query("host.metrics", params)["observation"]
        assert metrics["state"] == "available", f"{name}: metrics source unavailable"
        for key in ["load1", "memory_total_bytes", "memory_available_bytes"]:
            assert metrics["metrics"][key]["state"] == "available", f"{name}: {key} not fresh"
        profiles = query("resources.list", {"kind": "execution_profiles", "host": name})
        assert {entry["profile"]["name"] for entry in profiles["resources"]} == {"diagnostic", "operator", "activation"}
        assert all({"name", "max_timeout_seconds", "output_limit_bytes", "user", "privileged", "interpreter", "working_roots", "path"} <= set(entry["profile"]) for entry in profiles["resources"])
        diagnostic = next(entry["profile"] for entry in profiles["resources"] if entry["profile"]["name"] == "diagnostic")
        assert diagnostic["user"] == "maxops-runner" and not diagnostic["privileged"]
        assert diagnostic["path"] and "tailscale" in diagnostic["path"] and "systemd" in diagnostic["path"]
        probes = query("resources.list", {"kind": "diagnostic_probes", "host": name})
        assert {"tailscale-status", "ipv6-addresses", "ipv6-routes", "memory"} <= {entry["probe"] for entry in probes["resources"]}
        print(f"PASS {name}: {units['total']} observed units ({coverage}), agent/executor, profiles, service details, bounded logs, metrics and deployment profile", flush=True)
    failed = query("units.failed")
    assert {entry["host"] for entry in failed["hosts"]} == expected_hosts
    assert all(entry["state"] == "available" for entry in failed["hosts"])
    alerts = query("alerts.active")
    assert all(alert["labels"]["instance"] in expected_hosts for alert in alerts["alerts"])
    request("/v1/operations", credential=None, expected=401)
    request("/v1/operations", credential="invalid-fixture-" + "x" * 32, expected=401)
    for operation in ["host.facts", "host.metrics", "units.list", "deploy.status"]:
        query(operation, {"host": "maxops-ungranted-fixture"}, expected=403)
    for operation in ["units.status", "units.logs"]:
        query(operation, {"host": inventory[0]["name"], "unit": "../invalid.service"}, expected=400)
    query("resources.list", {"kind":"execution_profiles"}, expected=400)
    recent = request("/v1/execute?view=summary", {"op":"events.recent", "params":{"limit":5}})
    assert len(recent["events"]) <= 5
    assert all("payload" not in event for event in recent["events"])
    if recent["events"]:
        detail = query("events.get", {"event_id":recent["events"][0]["event_id"], "limit":1024})
        assert len(detail["text"].encode()) <= 1024
    query("units.restart", {"host": inventory[0]["name"], "unit": "maxops-agent.service"}, expected=400)
    # Unknown JSON fields are rejected by the typed HTTP extractor before dispatch.
    query("host.metrics", {"host": inventory[0]["name"], "query": "up"}, expected=422)
    print(f"PASS {len(expected_hosts)}-host fleet: protocol-2 discovery, read-only operations, executor discovery and authorization boundaries; no test notifications sent")
    assert not restart_history, "agent restart history: " + "; ".join(restart_history)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"FAIL: {error}" if isinstance(error, AssertionError) else f"FAIL: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
