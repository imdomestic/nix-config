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

There is no mutation API, MCP adapter or notification receiver enabled.
The rest of the fleet is not yet in this pilot's inventory.

## Max integration configuration

`nixos/hosts/h610/maxops.nix` configures a separate `max` client, restricted to
h610 and the existing readable services, with its own SOPS `maxops/max_token`.
`services.max.maxops` passes that token through `LoadCredential`, not an inline
environment value or a sandbox mount. Only QQ conversation `611798505` is allowed;
private chats and owners outside that conversation receive no maxops tools.
Endpoints mirrored onto this QQ conversation share its results and permission.

The allowlist is `services.max.maxops.allowedGroups`; it overrides YAML through
`MAX_MAXOPS_ALLOWED_GROUPS`. To manage it with `maxctl reload` instead, set the
native option to `null` and configure `maxops.allowed_groups` in the hand-managed
`/var/lib/max-bot/max.yaml`. An empty list denies everyone. The native URL,
enable flag and credential path still apply even with that hand-managed file.

The Max input includes the group-scoped HTTP integration. Deployment requires
both Max and the hub to load the dedicated client credential. The original pilot
results below predate this integration; keep its acceptance evidence separate.

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

## Verified on 2026-09-05

The original acceptance script passed in full after deploying `c484672`.

| Check | Result |
| --- | --- |
| All 17 NixOS host configurations | Evaluation passed |
| h610 SOPS declarations | 49 keys across three files verified |
| macOS devenv checks and Linux Nix package tests | 15 nextest tests passed on each platform |
| Real hub, agent and packaged CLI | All six operations passed |
| Live observations | Seven allowlisted units, zero failed; exporter `up` with a fresh sample time |
| Authentication and scope | Missing/wrong/cross-purpose credentials, ungranted host/unit and injected identity rejected |
| Journal and privileges | Plain startup message read, limits enforced; non-root processes, empty effective/bounding capabilities and NoNewPrivileges |
| Tailnet access | Health 200, unauthenticated catalog 401; agent bound only to loopback |
| Existing services | Max, nginx, Prometheus, Alertmanager and Tailscale remained active with unchanged PIDs |

The verified running system and persistent system profile both point to
`/nix/store/piz1jcqg1pnfh4k906kw1yzlqv5caskg-nixos-system-h610-26.05.20260622.3426825`.
Both daemon executables resolve to the pinned package
`/nix/store/lk0fq794k94pjmn9lpjgdv8aigr5bx83-maxops-0.1.0`, with zero automatic restarts.
The VM test was not run: this host has no `/dev/kvm`.
