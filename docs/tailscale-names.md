# Tailscale names

The managed fleet uses `tsName = "<node>.inner.imdomestic.com"` in each host
registry entry. `lib/my-host.nix` forwards it as `config.my.host.tsName` to all
four evaluators. A non-null name enables the existing deployment, telemetry and
Tailscale defaults. No allocated Tailscale IP is required in this inventory.
Do not assume the registry name equals the actual MagicDNS name: verify the
node's `DNSName` first, especially for dual-boot machines (`b650` and
`b650-windows` are different nodes).

Deployment destinations, maxops/worker URLs, Prometheus targets, Alertmanager
peers, Grafana data sources, ping targets and the migrated h610/tank consumers
use fully qualified names. Explicit `instance`/`peer` labels retain the short
registry names, preserving dashboard and alert identities. Ping remains IPv4
only, with DNS refreshed every 30 seconds. Nginx remote upstreams use a shared
zone and `resolve` so a peer's address change does not require an nginx restart.

## Listeners

Services continue to bind specific local Tailscale addresses. Programs that
accept hostnames receive `tsName` through their native module settings.
`my.tailscale.bindServices` adds a startup check: the IPv4 DNS answer must match
an address actually assigned to local `tailscale0`. Missing DNS, a stale answer
or an answer for another machine fails startup; it never falls back to a public
or wildcard listener. The shared client declares `--accept-dns=true` through
`extraSetFlags`. It does not sign in or create nodes.

For applications requiring numeric IPs:

- Grafana: its native file provider reads the checked current address from
  `/run/grafana/tailscale-bind-address`, generated before startup. This also
  satisfies the embedded API server, which rejects hostnames.

- maxops agent/hub: a package wrapper resolves the native JSON config's `listen`
  field, writes a mode-0600 runtime config, and execs the original binary. All
  other native settings and credential paths are retained.
- Alertmanager: the wrapper supplies a numeric gossip advertise address. Its
  cluster peers and public URLs remain names.
- Headplane 0.6.2: the wrapper uses its native `HEADPLANE_SERVER__HOST`
  environment override. The static host is loopback, a safe default even if the
  wrapper is bypassed.

These are startup bindings. If the *local* node's address changes while a
service is running, restart its listeners after MagicDNS converges. This
migration does not add an address-change supervisor. Replacing a node also
requires removing/renaming its old Headscale record to preserve the intended
DNS name; neither hostname reuse nor DNS is authentication.

## Bootstrap listeners and h610 aliases

`my.tailscale.guardedTCPServices` declares private ports for services that must
start before MagicDNS. The same guard protects r6s mihomo's controller on 9090;
mihomo supplies bootstrap DNS and must not wait for its own resolver.

Nginx serves the public Headscale control endpoint on 8443. It must start without
waiting for the Tailscale client. Its private web ports 80/443 therefore listen
on wildcard IPv4, protected by an independent `inet` nftables input table that
drops traffic arriving outside `lo` and `tailscale0`. The table applies to both
IPv4 and IPv6 regardless of `networking.firewall.enable`. Nginx is ordered after
and bound to nftables; stopping that service stops nginx before removing the
rules. The public 8443 endpoint is unaffected.

Headscale extra DNS records require addresses. The `headscale-local-dns` timer
updates `gaoji` and `kennethbot` aliases from the client's current self address,
using the native `dns.extra_records_path` setting. The file starts as `[]` on a
fresh installation so it cannot prevent Headscale from starting. Headscale
watches subsequent atomic updates; alias convergence can take a timer interval.

## PostgreSQL and NFS

The h610/tank PostgreSQL HA configuration now uses MagicDNS names for listeners,
monitor/replication endpoints and exact HBA hostname rules. HBA requires working
reverse **and** forward DNS, in addition to the existing TLS and password checks.
Startup converges the existing keeper's mutable hostname, monitor URI and listen
address using `pg_autoctl config set` and `pg_autoctl set node metadata`; the
latter also updates the monitor while the keeper is stopped. Neither command
registers or recreates members.
The password file includes dynamically resolved numeric peer addresses during
rolling migration, while older peers still advertise numbers. Before activation,
verify both hosts' PTR answers and forward lookup results. Roll out the database
nodes one at a time and check replication after each activation.

The archive NFS mount/export use names too. The exporter waits for the client
name before reloading exports; the upstream unit otherwise ignores resolution
failures. The host-network Qwen container explicitly uses the Tailscale DNS
server because Docker strips the host's loopback resolver. NFS keeps established mounts and
export resolution as runtime state: refresh the export and remount if a server
or client is replaced with a new address.

## Scope and verification

This covers the ten previously `tsIp`-managed hosts and their consumers. WSL's
separate inference setup was not in that inventory and retains its independent
`tailnetAddress`; changing its service lifecycle is a separate migration.
Tailscale range constants, loopback addresses, WireGuard addresses and subnet
routes are not allocated node identities and remain numeric.

Run `python3 scripts/test-tailscale-bind.py`, then evaluate the affected system
closures with `nix eval --raw .#nixosConfigurations.<host>.config.system.build.toplevel.drvPath`.
Changes under `home/` are not needed. No automatic registration, pre-auth key
creation, database restoration or system activation is part of this change.
