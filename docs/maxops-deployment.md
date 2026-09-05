# maxops deployment

The initial deployment runs the read-only hub and agent on h610. The input
`github:HCHogan/maxops` follows this repository's nixpkgs; `flake.lock` pins the
application revision. Configuration lives in `nixos/hosts/h610/maxops.nix` and
uses the upstream native NixOS modules.

- Hub: `http://100.64.0.3:9721`, exposed through the Tailscale interface.
- Agent: `http://127.0.0.1:9720`, reachable by the colocated hub.
- Inventory and the `hank` principal are scoped to h610 and seven named services.
- Prometheus and Alertmanager use h610's existing monitoring endpoints.
- Separate agent and client credentials are encrypted in `secrets/hosts/h610.yaml`.
  SOPS installs them under `/run/secrets/maxops`; systemd supplies service copies
  with `LoadCredential`. Hank can read only the client token, mode `0400`.
- Logs are enabled for the allowlisted services. The agent's journal group is
  a broader process-level read permission; the HTTP allowlist restricts its API.

There is no mutation API, MCP/QQ integration or notification receiver enabled.
The rest of the fleet is not yet in this pilot's inventory.

## Use

On h610 as hank:

```sh
nix shell github:HCHogan/maxops -c maxopsctl \
  --url http://100.64.0.3:9721 \
  --token-file /run/secrets/maxops/hank_token fleet.overview
```

Replace `fleet.overview` with `operations`, `units.failed`, `alerts.active`,
`host.facts --host h610`, `units.status --host h610 --unit max.service`, or
`units.logs --host h610 --unit maxops-agent.service --lines 20`.

## Acceptance

Run `scripts/check-maxops.py` on h610 as root, passing `--host h610`,
`--hub-url http://100.64.0.3:9721` and `--cli <package>/bin/maxopsctl`.
It uses runtime credential files without printing their contents, checks all six
queries against the real host, and reports journal test results without printing
journal bodies. It also checks denial cases and the live processes' privileges.
It does not restart services or send notifications.

The package's nextest suite and NixOS configuration evaluation are separate
checks. The upstream VM test still needs a Linux KVM builder; a successful
production smoke test does not establish the VM test passed.

The first live run exposed and reproduced two integration differences; see
[the dated incident record](incidents.md#maxops-pilot-acceptance). The pinned
`c484672` revision fixes Prometheus metric-name matching and daemon ANSI output.
