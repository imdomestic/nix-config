# Tokyo migrations

## 2026-11-17 · Aliyun replacement

The provider reclaimed the previous Tokyo VPS. Its replacement is still the
same `tokyo` registry host, now on Aliyun at `8.216.32.13` (2 vCPUs, 4 GiB
RAM, 100 GiB virtio disk, UEFI, IPv4 DHCP behind 1:1 NAT). The system was
built on tank and installed with nixos-anywhere, disko and copied host keys.
The new machine's SSH-derived age recipient replaces the old one in the Tokyo
and shared SOPS files; this does not revoke plaintext or old ciphertexts that
were accessible to the reclaimed machine.

The canonical public endpoint is `tokyo.imdomestic.com`; its stale AAAA
record was removed because the new VM has no public IPv6. The old
`sh.imdomestic.com` A record remains pointed at the new address temporarily
for existing clients; it is not used by the current configuration. WireGuard
and Xray credentials and internal reverse-tunnel identifiers remain unchanged.
Existing clients need their configurations deployed before the compatibility
record can be removed. The new DERP certificate is for the canonical name,
so the compatibility record does not support old DERP clients using `sh`.

Headscale node 47 was expired, its exit routes withdrawn and its name changed
to `tokyo-retired-47`. The replacement is node 54 at `100.64.0.13` with
approved exit routes. Headscale's Tokyo peer-relay grant follows that address.
Because h610's latest system switch had just failed (see
[gaoji-qq-official.md](gaoji-qq-official.md)), only Headscale was restarted:
`/etc/systemd/system.control/headscale.service.d/50-tokyo-cutover.conf` points
its unchanged binary at `/var/lib/headscale/tokyo-cutover/`, copies of the
running config with only the DERP endpoint and relay policy address changed.
The declarative equivalents are in `hosts/h610/system.nix`. On the next
planned h610 deployment, remove this override and restart Headscale after the
new generation is active; otherwise it masks future config changes.

At installation the new system booted, SSH and SOPS worked, Xray and DERP
started, and the DERP TLS probe succeeded locally. Public TCP 3444, 3445,
54322, 54324, 8443 and 25565 timed out despite listening: Aliyun ingress
rules still need attention. Homes for hank, kenneth and fendada were built on
tank and activated. Linwhite's home was not activated: the new account lacks
its SOPS SSH identity, and its imported Pi configuration also requests Hank's
AGY key, whose SOPS recipients do not include linwhite. Resolve those access
boundaries before activating it; do not copy a personal private key to the VPS.

## 2026-10-02 · replacement for Shanghai

The expired Shanghai VPS is replaced by `tokyo` at `43.130.229.141`.
The new machine has two vCPUs, 2 GiB RAM, a 40 GiB virtio disk and a
30 Mbit/s advertised connection. Debian 13 was the bootstrap environment.
The observed boot mode was BIOS, with interface `eth0` and DHCP behind the
provider's public-IP NAT.

The registry, standalone homes and deploy node are named `tokyo`.
`sh.imdomestic.com` remains the public compatibility endpoint for existing
WireGuard and Xray clients. WireGuard retains `10.0.0.1/24`, peer keys and
preshared keys. The existing DERP region ID 611 is retained with the Tokyo
label and new public IP.

Xray keeps the original routing:

| TCP port | Purpose | Exit |
| --- | --- | --- |
| 3444 | Reverse bridge from gizmo | gizmo tunnel |
| 54322 | User entry | gizmo |
| 3445 | Reverse bridge from rpi4 | rpi4 tunnel |
| 54324 | User entry | rpi4 |

The host itself and its Tailscale exit-node traffic use the local Tokyo
connection. DAE is not imported or enabled. Tunnel domain names remain
`reverse-sh.hank.internal` and `reverse-sh-au.hank.internal` so the existing
bridge endpoints continue to match.

## Installation

Build on `tank`, never on the 2 GiB target. The disk layout is declared in
`hosts/tokyo/disk-config.nix`: GPT, BIOS boot partition, 512 MiB FAT ESP,
4 GiB swap and ext4 root. Disko selects GRUB's `/dev/vda` device; specifying
it again in hardware configuration would duplicate `mirroredBoots` devices.

Use nixos-anywhere with the prebuilt system and disko store paths,
`--copy-host-keys`, `--build-on local` and `--no-disko-deps`. The Debian host
keys are preserved so the newly encrypted SOPS secrets can be decrypted
on first boot. No initial login password is stored in the repository.

The new host age recipient replaces the expired host in `.sops.yaml`;
`secrets/hosts/tokyo.yaml` and shared secrets are re-encrypted accordingly.

## Verification

Before installation: NixOS configurations evaluate, all 112 declared Tokyo
secrets exist, all four Xray inbounds validate, and both reverse-tunnel
names match their bridge configurations. Runtime acceptance is recorded
after installation below.

The provider's public IPv6 address and link-local default gateway are explicit
in the networkd configuration because DHCPv6 alone returned only a ULA.
Both IPv4 and IPv6 Internet access were verified after activation.

Runtime checks on 2026-10-02:

- NixOS 26.05 booted from disk; the active generation matches the evaluated
  Tokyo system. No failed units on Tokyo.
- DAE is absent; direct IPv4 egress is `43.130.229.141`.
- Headscale node 47, MagicDNS `tokyo.inner.imdomestic.com`, IPv4 `100.64.0.41`.
  IPv4 and IPv6 exit routes were approved.
- TCP 3444, 3445, 54322, 54324 and 8443 are reachable after the owner opened
  the cloud firewall. DERP HTTPS returns 200 with a valid Let's Encrypt
  certificate, expiring 2026-12-31.
- Grafana gateway `http://100.64.0.41:3000/login` returns 200.
- Existing WireGuard clients were refreshed to the new public endpoint;
  successful handshakes were observed.
- Both Xray entries were tested with the existing client credentials:
  Japan `219.104.128.80`, Sydney `27.122.122.170`.
- REALITY uses the compatible CDN alias documented in
  [incidents.md#tokyo-reality-cdn](incidents.md#tokyo-reality-cdn).

All four standalone homes (hank, linwhite, kenneth and fendada) were built
on tank and activated on Tokyo. Remaining uncached paths were transferred
as one compressed Nix export stream to avoid repeated cross-border SSH
round trips.

H610 was switched to the updated declarative configuration. Its Headscale
process was restarted once more after activation because a service recovery
had started the old command while the system switch was still in progress.
The running command and the client-visible DERP map were checked separately.

An unrelated existing `qq-bot-postgres-health` failure on h610 reports
`wait_primary`. Its journal already contains the same unhealthy state at
2026-10-02 12:40 UTC, before this installation and before the h610 switch.
No database state or failover roles were changed during this migration.
