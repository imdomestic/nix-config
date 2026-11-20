# tokyo

The Japanese VPS, registry host `tokyo`. Since 2026-11-17 it runs on Aliyun at
`8.216.32.13`: 2 vCPUs, 4 GiB RAM, 100 GiB virtio disk, UEFI, IPv4 DHCP behind
1:1 NAT (the host never sees its public address), no public IPv6. The public
name is `tokyo.imdomestic.com`; on the tailnet it is `100.64.0.13`.

Before that it was `43.130.229.141` at another provider (2 GiB, BIOS boot), which
replaced the expired Shanghai VPS on 2026-10-02 and was reclaimed on 2026-11-17.
The old `sh.imdomestic.com` name and `sh` tunnel identifiers are no longer used
(`docs/decisions.md#legacy-cleanup-2026-11`).

## What runs here

| Port | Purpose |
| --- | --- |
| TCP 3444 / 54322 | Xray: reverse bridge from gizmo (Japan exit) / user entry |
| TCP 3445 / 54324 | Xray: reverse bridge from rpi4 (Sydney exit) / user entry |
| TCP 8443, UDP 3478 | derper, the DERP region h610's Headscale advertises; clients are checked against Headscale |
| UDP 40000 | Tailscale peer relay for Sydney ↔ tank (`docs/incidents.md#sydney-tank-peer-relay`) |
| TCP/UDP 27015, 64738 | public entry for cs2 and mumble, DNAT to tank's tailnet address |
| TCP 25565 | Minecraft gate (`system/modules/minecraft/gate.nix`), backend on encore |

The host and its exit-node traffic go out directly; dae is not imported. The
`monitor-gateway` role adds the Grafana failover entry (`:3000`, tank first,
then h610).

Aliyun's security group must open the same ports; the host firewall alone is
not enough. derper only answers STUN requests that carry `SOFTWARE=tailnode`
and the right fingerprint, so a hand-made STUN probe timing out does not mean
UDP is blocked (`docs/incidents.md#tokyo-wireguard-shared-identity`).

## Installation

Build on `tank`, never on the target. The disk layout is
`hosts/tokyo/disk-config.nix` (disko: GPT with a BIOS boot partition, 512 MiB
ESP, 4 GiB swap, ext4 root). Disko picks the boot device itself; naming it
again in the hardware configuration would duplicate `mirroredBoots` devices.

Use nixos-anywhere with the prebuilt system and disko store paths,
`--copy-host-keys`, `--build-on local` and `--no-disko-deps`. Keeping the
bootstrap system's host keys lets the newly encrypted SOPS secrets decrypt on
first boot. If the host key does change, put its age recipient in
`hosts.tokyo.ageKey`, run `just sops-config` and `sops updatekeys` the files it
reads. No initial login password is stored in the repository.

After a replacement:

- In Headscale, expire and rename the old node (as `tokyo-retired-47` was),
  withdraw its exit routes and approve the new node's. The peer-relay grant in
  `hosts/h610/system.nix` follows the new address.
- The derper certificate is for `tokyo.imdomestic.com`; clients must use that name.
- Build all four homes on tank and copy them over. Fetching path by path across
  the border is slow; send the uncached remainder as one compressed
  `nix-store --export` stream.
