#!/usr/bin/env python3
"""Read-only acceptance on the pilot host; never print tokens or journal bodies."""
import argparse
import json
from pathlib import Path
import subprocess
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--host", required=True)
parser.add_argument("--hub-url", required=True)
parser.add_argument("--agent-url", default="http://127.0.0.1:9720")
parser.add_argument("--client-token-file", default="/run/secrets/maxops/hank_token")
parser.add_argument("--agent-token-file", default="/run/secrets/maxops/agent_token")
parser.add_argument("--cli", required=True)
args = parser.parse_args()
client_token = Path(args.client_token_file).read_text().strip()
agent_token = Path(args.agent_token_file).read_text().strip()
assert client_token != agent_token
opener = build_opener(ProxyHandler({}))


def request(base, path, token=None, body=None, expected=200):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    data = None if body is None else json.dumps(body).encode()
    try:
        with opener.open(Request(base + path, data=data, headers=headers), timeout=15) as response:
            status, payload = response.status, response.read()
    except HTTPError as error:
        status, payload = error.code, error.read()
    assert status == expected, f"{path}: expected HTTP {expected}, got {status}"
    return json.loads(payload) if expected == 200 else None


def execute(op, params=None, expected=200):
    return request(args.hub_url, "/v1/execute", client_token,
                   {"op": op, "params": params or {}}, expected)


def system_property(unit, prop):
    return subprocess.check_output(["systemctl", "show", unit, "--value", "-p", prop], text=True).strip()


for base in (args.hub_url, args.agent_url):
    request(base, "/healthz")
for token in (None, "invalid-test-token-" + "x" * 32, agent_token):
    request(args.hub_url, "/v1/operations", token, expected=401)
for token in (None, client_token):
    request(args.agent_url, "/v1/snapshot", token, expected=401)
operations = request(args.hub_url, "/v1/operations", client_token)["operations"]
assert len(operations) == 6
assert "/v1/execute" in request(args.hub_url, "/v1/openapi.json", client_token)["paths"]
print("PASS: liveness, six-operation catalog, OpenAPI and separate credential enforcement")

snapshot = request(args.agent_url, "/v1/snapshot", agent_token)
facts = execute("host.facts", {"host": args.host})
assert facts["host"] == snapshot["host"] == args.host
assert facts["facts"]["kernel"] == Path("/proc/sys/kernel/osrelease").read_text().strip()
assert facts["facts"]["system_closure"] == str(Path("/run/current-system").resolve())
assert abs(facts["facts"]["uptime_seconds"] - float(Path("/proc/uptime").read_text().split()[0])) < 30
for unit in snapshot["units"]:
    status = execute("units.status", {"host": args.host, "unit": unit["unit"]})["unit"]
    assert status["active_state"] == system_property(unit["unit"], "ActiveState")
failed = execute("units.failed")["hosts"]
assert len(failed) == 1 and failed[0]["state"] == "available"
assert {u["unit"] for u in failed[0]["units"]} == {
    u["unit"] for u in snapshot["units"] if u["active_state"] == "failed"
}
overview = execute("fleet.overview")
assert overview["prometheus"] == "available"
assert len(overview["hosts"]) == 1 and overview["hosts"][0]["host"] == args.host
assert overview["hosts"][0]["agent"]["state"] == "reachable"
assert overview["hosts"][0]["agent"]["failed_units"] == len(failed[0]["units"])
assert overview["hosts"][0]["exporter"]["state"] == "up"
alerts = execute("alerts.active")["alerts"]
assert all(a["labels"]["instance"] == args.host for a in alerts)
print(f"PASS: real systemd status ({len(snapshot['units'])} units), closure, uptime, Prometheus and Alertmanager")

log_params = {"host": args.host, "unit": "maxops-agent.service", "lines": 50, "since_seconds": 3600}
entries = execute("units.logs", log_params)["entries"]
assert 0 < len(entries) <= 50
assert any("agent listening" in str(entry["message"]) for entry in entries)
assert all(set(entry) == {"timestamp_us", "priority", "message"} for entry in entries)
execute("units.logs", dict(log_params, lines=201), expected=400)
execute("units.logs", dict(log_params, since_seconds=86401), expected=400)
execute("host.facts", {"host": "maxops-out-of-scope"}, expected=403)
execute("units.status", {"host": args.host, "unit": "sshd.service"}, expected=403)
execute("units.logs", dict(log_params, unit="sshd.service"), expected=403)
request(args.agent_url, "/v1/logs", agent_token, dict(log_params, unit="sshd.service"), 403)
request(args.agent_url, "/v1/logs", agent_token, dict(log_params, host="maxops-out-of-scope"), 403)
request(args.hub_url, "/v1/execute", client_token,
        {"op": "host.facts", "params": {"host": args.host, "identity": "root"}}, 422)
execute("units.restart", {"host": args.host, "unit": "maxops-agent.service"}, expected=422)
print("PASS: real journal access, output limits, host/unit scope, identity injection and unknown mutation rejection")

for unit in ("maxops-agent.service", "maxops-hub.service"):
    assert system_property(unit, "ActiveState") == "active"
    assert system_property(unit, "DynamicUser") == "yes"
    assert system_property(unit, "NoNewPrivileges") == "yes"
    pid = system_property(unit, "MainPID")
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
    assert all(int(uid) != 0 for uid in status["Uid"].split())
    assert int(status["CapEff"].strip(), 16) == 0
    assert int(status["CapBnd"].strip(), 16) == 0
    assert status["NoNewPrivs"].strip() == "1"
cli_facts = json.loads(subprocess.check_output([
    args.cli, "--url", args.hub_url, "--token-file", args.client_token_file,
    "host.facts", "--host", args.host], text=True))
assert cli_facts["facts"]["system_closure"] == facts["facts"]["system_closure"]
print("PASS: live unprivileged processes, empty capabilities, NoNewPrivileges and packaged CLI round trip")
