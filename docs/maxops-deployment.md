# maxops deployment

The current design and Max/maxops ownership boundary are in
[maxops.md](maxops.md). Sections below retain dated rollout evidence; a historical
pilot's permissions or operation count must not be read as the current contract.

## Diagnostic execution and task notice review (2026-09-11)

This release pins Max `346a336` and maxops `36964fe` in nix-config `a509373`.
The fleet also incorporates upstream configuration changes through `3c2f3c5`;
`69f9356` fixes the diagnostic probe launcher. All 17 NixOS configurations
evaluated successfully. Standalone Home Manager profiles were not activated by
this release.

Diagnostic profiles now expose their user, privilege, interpreter, working roots
and PATH. Their command environment includes systemd, iproute2, procps, jq,
network tools and Tailscale. Fixed probes use the absolute
`/run/current-system/sw/bin/env` launcher, satisfying Hub startup validation while
resolving commands from each target's diagnostic PATH. Probe output completeness
and missing evidence remain explicit in full results and compact job summaries.
Max distinguishes its task numbers from remote job UUIDs, retains uncertainty for
process-only results, and reviews both progress and result notices before output.

Local gates passed: 1,106 Max unit examples, 411 disposable-PostgreSQL integration
examples, full builds, lint, architecture checks, prompt-flow generation/check,
migration upgrade checks, 80 maxops native tests and 84 consumer compatibility
tests. The real NixOS VM test passed in 141.77 seconds; native Linux Max and both
maxops architectures built successfully.

### Rollout corrections

Interrupted transfers overlapping native builds left registered but incomplete
maxops package contents on h310 and tank. Both hosts were rolled back to working
systems, repaired from complete, locally verified binary-cache archives, and
activated again successfully. Subsequent activation checks verified the NAR
contents of every Max/maxops executable package before switching. Download cache
archives completely before repairing a store path; do not overlap streamed
imports with builds of the same output.

The first h610 transition retained old binaries but not their complete
configuration and migration bundle. It restarted Max, and the old process
encountered the new output fence. Hub rejected the bare diagnostic command names;
the final Hub binary enforced the same absolute-launcher constraint. The launcher
fix restored Hub startup. Future staged releases must preserve the old config
and migration paths as well as the executable, and validate the rendered Hub
configuration before activation. The final matching Max/Hub configuration
switched successfully; Max, runtime, Hub, Agent and Executor are active.

### Live acceptance and limits

Using Max's actual credential, all nine hosts passed discovery, loaded-unit
coverage, service details, bounded logs, fresh metrics, execution profile and
probe discovery, running/profile agreement, and authorization rejection checks.
Nine real diagnostic-profile jobs verified the expected non-root user and command
PATH. All 36 fixed probe executions produced complete output. One Shanghai bundle
correctly returned `partial` with `missing_evidence=["unit_logs"]` after a journal
timeout; a separate collection returned `complete`. The one-hour bounded journal
check also timed out once before the unchanged full fleet check succeeded.
These intermittent journal failures remain visible rather than being reported
as healthy evidence.

In real conversation 611798505, monitor task `#158` completed with an object-valued
observation. Child task `#159` retained `partial` and `result_scope=process_exit`
even though its remote job succeeded. Progress notice `322` and result notice
`324` each persisted a publish decision and exactly one conversation message.
Superseded progress notice `323` produced no output. Result notice `324` required
two attempts. This proves the live handoff and output fencing for this sample;
it is not evidence of an overall model-cost reduction. No synthetic conversation
messages were injected for acceptance.

b650 was rebooted by the user during the rollout. At boot its Agent retried once
because the Tailscale address was not yet assigned, then remained active with a
stable PID and restart counter. The strict zero-restart check therefore still
reports this explained startup history. The checker now completes all functional
checks before reporting restart history, retaining its nonzero exit status.

The production operational-health gate also remains non-green. The final recorded
snapshot has one unreviewed dispatch outcome, one unreviewed parked-media item,
and 22 unreviewed failed requests. Failed requests increased from 113 to 123
(unreviewed: 12 to 22) during the release window; this is not all historical debt.
The inspected failures report missing explicit request disposition. Dispatch
outcome-unknown increased from 11 to 12, including a lease expiry during the
transition. Delivery outcome-unknown remained 3,054, all reviewed. Expired leases,
overdue task deadlines, exhausted notices and unresolved active journal outcomes
were zero. These records were not deleted, replayed or accepted to turn the gate
green. Functional release acceptance and this operational backlog are distinct.

| Host | Final running system store hash |
| --- | --- |
| b650 | `rx8z1n5d2hxax0qqg3gchs70zdjvm96i` |
| h310 | `bzmff6hbgiah17pinaj5iwzz1cxlvvl8` |
| h610 | `5dzrr8rsvr3nhcwxq5vl074dcsji2in7` |
| r5s | `6drrnkbxzayjsa8vs8q6qbfilyblz6jr` |
| r5sjp | `djj5pqlx4kiipc9v3rpsz1qj044zm378` |
| r6s | `v0bi5zf3igf3drscd3hygdx724jk7icg` |
| rpi4 | `z330yk49iyk5n9cc10dna7myan7aya52` |
| shanghai | `16ibhdqbcdb1jrv7kl4sysaaw8rbcnwa` |
| tank | `xkqfqrqgixf2sahk5lyid2sk99b4ljxx` |

## Broad observations and diagnostic tool fixes (2026-09-08)

The release pins maxops `ebfd2fd` (45 operations, including the `c368fae`
permission/API changes) and Max `8ac010e`.
All nine managed hosts enable `readAllUnits` at both Agent and Hub; the old
curated lists remain independent `manageableUnits`. Observation covers loaded
systemd units and explicitly configured names, including timers and targets.
The existing operator execution profile and conversation scopes are preserved.

Max retains safe structured permission reasons, completes already admitted
sibling calls before yielding to the durable job observer, and attaches bounded
job output to its report. The public API adds recent event summaries and bounded
event detail, paginated unit discovery with coverage metadata, and a conditional
host requirement for execution-profile discovery. Reporter instructions keep
subsequent diagnosis in the owning Operations task.

Fleet acceptance found that b650's expanded 74,415-byte snapshot could exceed
the 12-second transport deadline over the cross-region link. Five identical
queries succeeded four times, averaging 8.834 seconds including the timeout.
The follow-up `ebfd2fd` adds negotiated gzip between Agent and the shared client;
decoded response limits remain enforced. Its local gate passed 78 tests, including
wire compression, transparent decoding and rejection of oversized decoded bodies.
The same five queries after activation all returned HTTP 200, averaging 1.625
seconds (including the first 5.093-second request). An independent Agent wire
check transferred 6,868 bytes for 74,262 decoded bytes in 0.848 seconds. These are
bounded release samples, not a fleet-wide latency guarantee.

Initial local release gates passed: 1,095 Max unit examples, 331 disposable-PostgreSQL
integration examples, 37 refreshed Max maxops-contract examples, 76 Rust nextest
tests, full builds, lint, architecture checks, prompt-flow generation/check,
lock-pin checks and the real Hub/Max integration harness. Native Linux builds
and live fleet acceptance are recorded below after activation.

### Runtime evidence

The initial release used nix-config `c3080af`; `eeea4cc` pins the compression
follow-up. All 17 NixOS configurations evaluated again after synchronizing the
upstream PostgreSQL configuration fix `32522e3`. Independent GitHub fetches
reproduced both pinned source hashes. Final native x86_64 and aarch64 maxops
builds each passed 78 tests; the consumer's compatibility package passed all
82 tests. Its first parallel build hit an existing short-polling fixture timeout;
a complete build with a single build slot passed without changing or skipping
tests. The final real NixOS VM test passed (139 seconds), and Max's Linux package
built successfully.

All nine running system closures and persistent system profiles match the
release outputs below. Live Agent configuration enables `read_all_units` on
every host; Agent/Executor manageable-unit lists exactly match the preserved
inventory policy. Agents/Executors are active and execute the new store paths.
Standalone Home Manager profiles were not switched.

h610 first activated an intermediate system retaining Max `8badc05`: Max PID
2807571 stayed running while new Hub PID 3312112 served the permission regression
checks. The final system runs Max PID 3336435 from
`p1j21sf6h0iaiq8wafqqany8kz9n23cq-max-0.18.0`; QQ reconnected at **12:51:29 HKT**.
Hub PID 3312112 stayed unchanged during the Max switch. The compression follow-up
then replaced it with Hub PID 3551533 from
`qfv26rs3i1aqjr1rlxfbsq98qvvqiha3-maxops-0.3.0`, keeping Max PID 3336435 unchanged.
An existing maxops job on h310 independently built the same pinned release; its build was allowed
to complete before activation. The final Max environment confirms query groups
611798505 and 650536599, alert group 611798505, and all nine notification hosts.

Using Max's actual credential, status and bounded logs returned HTTP 200 for
h610's PostgreSQL health/backup/restore-check services, stack target, Docker
service and health timer, plus r5s's nix-gc service. Missing execution-profile
host now returns `execution_profile_host_required`; an ungranted host returns
`host_not_permitted`. Recent event summaries remained bounded (15 events,
7,351 bytes in the first check) and contain no full payload.

The complete nine-host acceptance passed again after all nine compression
versions were activated, using Max's credential: protocol-2
catalog, unit coverage and discovery, Executor profiles, current service details,
bounded journals, fresh metrics, running/profile agreement and authorization
rejections. The first compression-era sweep hit a 10-second Shanghai journal
timeout; the same local journal query took 6.966 seconds, and three subsequent API
queries succeeded in 6.450, 3.541 and 0.555 seconds. The full rerun passed without
loosening limits or skipping checks. This suggests cold journal I/O contributed
to that isolated failure; gzip does not remove the existing journal timeout.

The initial h610 stage and Max switches returned exit 4 while a separate
PostgreSQL socket migration (`02d57d9`/`5943685`) still had bootstrap and health
checks targeting an unavailable socket. Later upstream maintenance landed
`32522e3`; the final compression switch returned 0. A fresh check then found
bootstrap successful and the PostgreSQL health service's last result successful.
The database node and monitor were not force-restarted by this release workflow.
Tank's last PostgreSQL health check still reported failure in the final fleet
failure view; this remains separate from Max/maxops activation acceptance.

Max's existing iMessage bridge remains unreachable. Its old process reported
one in-flight dispatch when shutdown draining timed out. Read-only health moved
from 2,361 to 2,385 delivery outcome-unknown records after the Max switch and 2,419
at the final read-only snapshot. Unresolved journal outcome-unknown briefly rose
from zero to one, then returned to zero. Dispatch unknowns (11),
parked media (385), failed requests (32) and sandbox unknowns (1) remain. These
records were neither deleted nor replayed to make the health gate pass; Max's
strict operational-health gate still fails.


| Host | Running system store hash |
| --- | --- |
| b650 | `shcy31n83qrf3m34bnygcb1ymav0w0hw` |
| h310 | `nc9v9fjscjaikklh02cai4pzzvq9ckka` |
| h610 | `kxc2j1rg61yk67862l7bbbs13azsyp37` |
| r5s | `pwv475qann7b4vf42m429h66vaxk9wpi` |
| r5sjp | `66cv5hrs58ck41rzfba939lhwxsgy1jz` |
| r6s | `72cdxyq54ll3hd2q4ydccv1v89w80yhn` |
| rpi4 | `dm22ljhmawgiaabayzhzpl6h1c4425g0` |
| shanghai | `2mnp1vbqqw3vqhyhnr4hmx7q0smrwhpg` |
| tank | `iqz1qssza2z438yahi57y5n07w6b6v8d` |

## Skill bundles and public client API release (2026-09-07)

The release pins maxops `dae8335` (0.3.0, protocol 2, 43 operations) and Max
`277f61b` (0.18.0). All 17 NixOS configurations evaluated successfully after
rebasing onto the current nix-config remote. The managed inventory remains
**b650, h310, h610, r5s, r5sjp, r6s, rpi4, shanghai and tank**, with the Hub and
Max on h610. All nine systems were activated from nix-config `0cec340`;
final running closures and persistent system profiles matched their evaluated
outputs. Standalone Home Manager profiles were not switched.

Max now loads complete fixed skill tool bundles on `use_skill`, including all
permitted maxops tools and instructions. The old three generic RPC tools are
replaced by typed definitions from the public catalog. Host-owned submission
identities and durable Operations tasks observe remote jobs through `jobs.wait`;
the frontend model interprets their results. The release also fixes durable
`kill --all` settlement so cancellation releases frontend ownership.

The public API adds compact/paginated discovery, resource discovery, job waits,
events/results, bounded text logs, structured errors and durable `deploy.run`.
Roll out Agent/Executor first, then Hub, then Max. Back up every maxops SQLite
store consistently before the migration; keep Max PostgreSQL backup and live
read-only health evidence separate from disposable-DB tests.

The conversation allowlist remains **611798505 and 650536599**; fleet alerts go
to **611798505** only. Final process environment must confirm both separately.
Old durable management grants fail closed after the Max effect fingerprint
change; do not rewrite grants or replay historical work to conceal this.

### Runtime acceptance

Remote Agents/Executors were upgraded first. h610 then activated an intermediate
closure with the old Max input explicitly overridden to `b24cddc`, allowing Hub
acceptance while Max PID `544279` stayed up. The final switch only needed to restart Max:
PID `1726528`, package `m4q81yqlg7q4y7bvv4iqmg05xgnhcdbb-max-0.18.0`.
Hub PID `1707468` stayed unchanged during that final switch. Max's authenticated
QQ websocket reconnected at **14:07:00 HKT** (2026-09-07).

All Agent/Executor processes used `8ri0v4qil9q7pr1mbhz53prwdkrag77v-maxops-0.3.0`
on x86_64 or `2ykaaflyg88nn2h92l5nyls51qfwj8dr-maxops-0.3.0` on aarch64,
with active state and `NRestarts=0`. Hub and all nine Executor SQLite databases
applied migration 4 and passed `quick_check`. Consistent pre-migration backups
passed `integrity_check` under `/var/backups/max-fleet-20260907-0cec340/` on each
host. h610 also holds the 787,082,041-byte custom-format Max PostgreSQL backup;
`pg_restore --list` read its table of contents successfully.

| Host | Final system store hash |
| --- | --- |
| b650 | `h1b341ybfzh9qwgyg86fgfg919i64w9v` |
| h310 | `6in8fjyjykbcv3f71ygk31vhahb7cwzc` |
| h610 | `ygb567vvbl9c24b0qk7dc8w179vxfxmh` |
| r5s | `jid2i04jqlzb9s20ifb368g5qnmnypg8` |
| r5sjp | `p0bzhbswaxfgrqsk0s5wv91vccp7c5aa` |
| r6s | `y8j13a3smr97yx00xvlpiybdah1gwy27` |
| rpi4 | `w2ld05vv1r1vmajvhmfdrxxds6amk5aw` |
| shanghai | `hj8k6cqimv8rl48bk5kf713msakfwpxj` |
| tank | `fbln6baajdiij5wmqgqyv20gz5y98h0f` |

`scripts/check-maxops-fleet.py` passed the nine-host runtime check: complete
protocol-2 tools catalog, summary pagination, resource/profile discovery through
each Executor, current agent service details, bounded journals, fresh metrics,
running/profile agreement, authentication and resource-scope rejection. One
initial request returned 502; the complete rerun passed. Invalid JSON fields
are rejected by the HTTP extractor with 422, while a valid mutation request
missing its submission key is rejected with 400; the acceptance script records
those separate boundaries and identifies failing operation/host pairs.

Nine diagnostic `true` jobs succeeded, one on each host. Repeating each submission
with `release-0cec340-probe-<host>` returned the same job ID. Each job's durable
wait, four persisted events, complete result (exit 0) and text log view passed.
These probes exercised execution without changing target services or sending
chat messages; they do not claim a production `deploy.run` failure/recovery drill.
Max's own credential returned all **43** operations: summary 9,691 bytes, tools
25,296 bytes, no response schemas or next page. Final process routing remained
`MAX_MAXOPS_ALLOWED_GROUPS=611798505,650536599` and
`MAX_MAXOPS_NOTIFY_GROUPS=611798505`.

Local gates: Max build, 1,044 unit examples, 321 real PostgreSQL integration
examples, HLint, Cabal check, prompt-flow generation/check and real Rust Hub/Max
HTTP integration passed. Both Linux architecture builds ran all 70 maxops tests
with zero failures or skips; all 17 NixOS configurations evaluated successfully.

Production Max operational health remains **not green**: 1,965 delivery outcomes
unknown, 11 dispatch outcomes unknown, 385 parked media records and 28 failed
requests. The delivery count was 1,964 in the preflight; the extra record
`163353` reported `HTTP connection timed out` and became unknown at
**13:56:43 HKT**, while the old Max was still running,
before the Max switch at **14:06:56 HKT**. Expired delivery/dispatch/frontend/task
leases, overdue task deadlines and unresolved active journal outcomes were all
zero after the switch. Historical records and grants were not rewritten, deleted
or replayed to improve these measurements.

## Fleet execution rollout (2026-09-07)

MaxOps 0.3 runs an Agent and Executor on all nine managed hosts. h610 remains
the only Hub. Hank and Max retain separate credentials but receive the same 38
operations and full capability set across the fleet; Kennethbot remains
observation-only.

- Every host has its own execution token in `secrets/maxops/<host>.yaml`, except
  h610, whose token remains in its host secret. h610 receives a separately
  encrypted copy of each remote token for Hub dispatch. Tokens stay in runtime
  files and systemd credentials.
- Manageable units are the explicit per-host `config.my.host.maxops.readableUnits`
  inventory. An enabled Executor does not grant access to unlisted units.
- Each host owns one logical repository and system deployment profile. The
  logical repositories share the public nix-config remote, but each workspace,
  check and build stays on its declared native-architecture Executor. Remote
  branch CAS still prevents concurrent publishers from overwriting one another.
- Commands use bounded diagnostic, root operator and root activation profiles.
  Deployments freeze Git and runtime baselines, build an exact derivation,
  activate its store path directly, run target-local checks and recover only
  while the change still owns the observed runtime.
- Human pushes, direct service actions and manual rebuilds remain supported.
  MaxOps re-observes the Git ref, running closure and persistent profile before
  mutation; stale or superseded work stops instead of overwriting another
  writer.
- b650 joined the managed inventory on 2026-09-07. Its explicit unit inventory
  covers MaxOps, Tailscale, node exporter, both Qwen service variants,
  llama-swap and its proxy, and NVIDIA persistence. Its repository and
  deployment remain native to b650 like every other host.

## Fleet expansion configuration (2026-09-06)

This section records the initial eight-host read-only rollout. The execution and
b650 additions above supersede its host count and operation/permission scope.

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

Everything in this section, including its Max integration configuration, records
the original pilot. Use the configuration review above for current permissions.

The initial deployment ran the read-only hub and agent on h610. The input
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
