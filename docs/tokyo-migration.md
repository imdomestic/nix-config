# Tokyo replacement for Shanghai

## 2026-10-02 migration

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
| 3444 | Reverse bridge from r5sjp | r5sjp tunnel |
| 54322 | User entry | r5sjp |
| 3445 | Reverse bridge from rpi4 | rpi4 tunnel |
| 54324 | User entry | rpi4 |

The host itself and its Tailscale exit-node traffic use the local Tokyo
connection. DAE is not imported or enabled. Tunnel domain names remain
`reverse-sh.hank.internal` and `reverse-sh-au.hank.internal` so the existing
bridge endpoints continue to match.

## Installation

Build on `tank`, never on the 2 GiB target. The disk layout is declared in
`nixos/hosts/tokyo/disk-config.nix`: GPT, BIOS boot partition, 512 MiB FAT ESP,
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
