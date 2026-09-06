# maxops deployment

## Fleet expansion configuration (2026-09-06)

All eight agents were activated in the initial fleet rollout (`707f986`),
with Max `15648d3` and maxops `8c08ae4`. The hub stays on h610. Registry entries enable
`maxops` for **h610, shanghai, r6s, r5s, rpi4, r5sjp, tank and h310**; all other
hosts remain disabled. The same registry fields generate agent policy, hub
inventory, the Max/hank client grants and notification host scope. There is no
second hand-maintained inventory or automatic enablement for every server.

- Each remote agent binds only its registry Tailscale address on 9720. h610's
  colocated agent stays on loopback. Agents remain DynamicUser, read-only and
  capability-free; no polkit/sudo mutation grant is introduced.
- `secrets/maxops/<host>.yaml` contains one distinct agent credential, encrypted
  only to administrators, that host and h610. Existing h610 credentials are
  unchanged. The hub and agents consume copies through `LoadCredential`.
- Query access is limited to QQ groups **611798505** and **650536599** and their
  mirrored conversations. Alert notifications target **611798505** only;
  **650536599** retains query access but no longer receives fleet alerts.
  Nine operations are available: the original six, plus
  `host.metrics`, `units.list`, and `deploy.status`. `units.status` adds PID,
  memory, restart and exit details. `fleet.overview` adds load/disk observations
  and cautious combined reachability, not a claim to diagnose power failures.
- Metrics have a separate `metrics:read` grant, exact host selectors and source
  timestamps. Arbitrary PromQL remains disabled. Deployment observations expose
  the running closure, persistent profile and profile generation; activation
  time remains null rather than inventing one from filesystem metadata.
- Both monitoring replicas send managed-host warning/critical alerts to
  `http://100.64.0.3:9721/v1/alerts`. Hub ingress and Max's loopback
  `127.0.0.1:9722/v1/alerts` use different credentials. Only h610/tank decrypt the
  ingress credential; only h610 decrypts the sink credential.
- Existing independent `my.monitoring.webhookUrl` configuration is preserved
  through a separate receiver. If it is still null, there is **no independent
  push channel**: Alertmanager retains/retries notifications, but an h610 outage
  interrupts the hub-to-Max notification path.
- Max receives alerts without an LLM call and commits dedupe plus canonical
  outbox publication atomically. HTTP 202 means queued, not delivered. Four-hour
  reminders match Alertmanager; resolutions/new episodes are distinct. Platform
  outcome-unknown delivery remains possible.

### Release and acceptance

Publish Max/maxops and pin both revisions before activation. Preserve incoming
unrelated changes after the required freshness review. Build on each required
architecture, activate remote agents before h610's new hub, then run the
read-only fleet acceptance. System and Home Manager remain separate.
Max migration 090 requires a current database backup; the old binary's schema
downgrade guard means a system-generation rollback alone is not a DB rollback.

For unpublished development changes, validate the working trees without recording
local paths in the deployment lock:

```sh
nix eval --raw .#nixosConfigurations.h610.config.system.build.toplevel.drvPath \
  --override-input max git+file:///Users/hank/Development/hs/max \
  --override-input maxops git+file:///Users/hank/Development/maxops \
  --no-write-lock-file
```

```sh
nix eval --json .#nixosConfigurations.h610.config.services.maxops-hub.hosts > /tmp/maxops-inventory.json
python3 scripts/check-maxops-fleet.py \
  --hub-url http://100.64.0.3:9721 \
  --token-file /run/secrets/maxops/hank_token \
  --inventory /tmp/maxops-inventory.json
```

The script never prints credentials/journal/alert bodies, changes services, or
sends test group messages. A failed or stale source fails acceptance rather than
becoming a healthy zero. Config evaluation is not a native build or a VM test;
h610 currently has neither KVM nor registered aarch64 binfmt. ARM builds need a
real ARM builder (or separately provisioned emulation), not an assumed capability.
Notification concurrency, rollback, retry and HTTP acceptance are tested with a
disposable PostgreSQL database, never by writing fixtures into the live ledger.

### Pre-release validation

- Max: `cabal build all`, 964 unit tests, 244 real PostgreSQL tests,
  `cabal check`, changed-area HLint and prompt-flow generation/check passed.
  An x86_64 Linux candidate also built on h610; its only source difference from
  the final locally tested tree is the equivalent `maybe fallback id` to
  `fromMaybe fallback` lint cleanup. No production Max process was replaced.
- maxops 0.2: 23 nextest tests, clippy, formatting, doctests and real hub/CLI
  smoke passed. Max's actual Haskell tool runners also passed against the new
  Rust hub, including scope denial and revoked group access.
- All 17 NixOS configurations evaluated with local Max/maxops input overrides;
  the eight target hosts passed SOPS key checks. Nine new credentials were
  verified distinct with exact recipient sets; existing host secrets unchanged.
- The native x86_64 Linux maxops package built on h610. Temporary unprivileged
  candidate services passed all nine operations against real D-Bus, journald,
  Prometheus and Alertmanager, including all ten metric families. They were
  stopped and their fixture credentials removed; production PIDs were unchanged.
- The planned Alertmanager configuration passed its packaged `amtool check-config`.
  Both VM-test derivations evaluated, but no VM test or ARM native build ran.
- Upstream publication, formal lock updates and production activation are
  separate release steps; these results do not claim fleet deployment or QQ
  end-to-end notification delivery.

### Production rollout observations

- The approved rebase retains Kennethbot 0.11.3. All 17 NixOS configurations
  evaluated with formal pins, and all eight target SOPS checks passed before
  publication. System profiles were activated; no Home Manager profile was deployed.
- Both x86_64 and aarch64 maxops packages built and ran their native tests.
  The eight agent services, h610 hub, Max and both Alertmanagers were active
  after the initial rollout, with zero automatic restarts for Max/maxops.
- Before migration 090, a PostgreSQL custom-format backup was written to
  `/var/lib/max-backups/pre-maxops-090-20260906T022710Z.dump` (730231910 bytes,
  mode 0600 in a root-only directory). `pg_restore --list` passed. Do not assume
  that rolling back the system generation also rolls back this migration.
- Live Max reports `15648d3`; migration 090 is present. The live notification
  probe verifies the eight-host scope, group 611798505, credential separation,
  HTTP authentication failures and hub-to-sink acknowledgement. It uses an empty
  alert payload, queues zero messages and sends no synthetic group notification.
- Six real alerts were durably recorded during rollout. At the initial check,
  QQ deliveries were `accepted_unconfirmed`; the six iMessage mirror deliveries
  were `outcome_unknown`. These are not end-to-end delivery confirmations, and
  uncertain deliveries were not manually resent. Historical parked-media and
  unknown-delivery debt is outside this rollout's remediation scope.
- Shanghai's approximately 4.1 GiB journal exposed a deadline mismatch: unchanged
  `journalctl` queries took about 8–9 seconds on cold reads, exceeding the original
  five-second limit. maxops 0.2.1 (`f7a2f73`) gives journals ten seconds and HTTP
  requests twelve, below Max's fifteen-second budget. Journal scope, service-manager
  entries, byte/line limits and concurrency limits are unchanged.
- Cross-border direct SSH to Shanghai, tank and r5s intermittently timed out;
  an h610 jump host worked. Prebuilt outputs were copied within the fleet over
  strictly host-key-checked SSH, without changing persistent Nix trust settings.
  Native builds from the published revision avoided slow remote derivation copies.
  Activating a prebuilt closure uses `nixos-rebuild switch --no-reexec --store-path`.

## Historical single-host pilot

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

### Max integration configuration

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

### Use

On h610 as hank:

```sh
nix shell github:HCHogan/maxops -c maxopsctl \
  --url http://100.64.0.3:9721 \
  --token-file /run/secrets/maxops/hank_token fleet.overview
```

Replace `fleet.overview` with `operations`, `units.failed`, `alerts.active`,
`host.facts --host h610`, `units.status --host h610 --unit max.service`, or
`units.logs --host h610 --unit maxops-agent.service --lines 20`.

### Acceptance

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

### Verified on 2026-09-05

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
