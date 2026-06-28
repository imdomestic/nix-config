# Build a systemd-networkd WireGuard *server* interface from a wg-quick style
# server `.conf` (as produced in the private `wg-config` input).
#
# Peer public keys / allowed IPs are read from the conf at evaluation time
# (they are not secret). Each peer's PresharedKey and the interface PrivateKey
# are extracted into their own files at build time so secrets stay sourced from
# the private input and out of the world-readable unit sections.
#
# NAT (the conf's `PostUp` iptables MASQUERADE) is intentionally *not* handled
# here; replicate it in the host via nftables / networkConfig.IPMasquerade.
#
# Usage:
#   let
#     wg = import ../../../lib/wgServer.nix { inherit pkgs lib; } {
#       conf = "${inputs.wg-config.outPath}/server.conf";
#       address = "10.0.0.1/24";
#     };
#   in {
#     systemd.network.netdevs."40-wg0" = wg.netdev;
#     systemd.network.networks."40-wg0" = wg.network;
#   }
{
  pkgs,
  lib,
}: {
  conf,
  address ? "10.0.0.1/24",
  name ? "wg0",
  listenPort ? 50722,
}: let
  lines = lib.splitString "\n" (builtins.readFile conf);

  # Collect every `Field = value` value across the conf, in file order.
  collect = field:
    lib.filter (x: x != null) (map (l: let
      m = builtins.match "${field} = (.*)" l;
    in
      if m == null
      then null
      else lib.head m)
    lines);

  pubkeys = collect "PublicKey";
  allowedIPs = collect "AllowedIPs";

  privateKeyFile =
    pkgs.runCommandLocal "${name}-privatekey" {} ''
      ${pkgs.gnused}/bin/sed -n 's/^PrivateKey[[:space:]]*=[[:space:]]*//p' ${conf} \
        | ${pkgs.coreutils}/bin/head -n1 \
        | ${pkgs.coreutils}/bin/tr -d '[:space:]' > "$out"
    '';

  # Nth (0-based) PresharedKey, matching the Nth [Peer] block in file order.
  pskFile = idx:
    pkgs.runCommandLocal "${name}-psk-${toString idx}" {} ''
      ${pkgs.gawk}/bin/awk -F ' = ' '
        /^PresharedKey/ { c++; if (c == ${toString (idx + 1)}) { printf "%s", $2; exit } }
      ' ${conf} > "$out"
    '';

  peers =
    lib.imap0 (idx: pub: {
      PublicKey = pub;
      PresharedKeyFile = pskFile idx;
      AllowedIPs = [(lib.elemAt allowedIPs idx)];
    })
    pubkeys;
in {
  netdev = {
    netdevConfig = {
      Kind = "wireguard";
      Name = name;
    };
    wireguardConfig = {
      PrivateKeyFile = privateKeyFile;
      ListenPort = listenPort;
    };
    wireguardPeers = peers;
  };
  network = {
    matchConfig.Name = name;
    address = [address];
  };
}
