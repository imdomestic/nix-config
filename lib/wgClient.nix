# Build a systemd-networkd WireGuard *client* interface from a wg-quick style
# `.conf` file (as produced in the private `wg-config` input).
#
# Secrets (PrivateKey / PresharedKey) are never written into this repo: they are
# extracted from the referenced conf at build time into their own key files, so
# they stay sourced from the private input and out of the world-readable
# `[WireGuard]`/`[WireGuardPeer]` unit sections.
#
# Usage (inside a host module):
#   let
#     wg = import ../../../lib/wgClient.nix { inherit pkgs; } {
#       conf = "${inputs.wg-config.outPath}/client_00065.conf";
#       address = "10.0.0.66/24";
#     };
#   in {
#     systemd.network.netdevs."40-wg0" = wg.netdev;
#     systemd.network.networks."40-wg0" = wg.network;
#   }
{pkgs}: {
  conf,
  address,
  name ? "wg0",
  serverPublicKey ? "i9ZU3WdqNxUyqtaM9F8Rbrs4ophdNpQ6wZeO/bV/jjQ=",
  endpoint ? "sh.imdomestic.com:50722",
  listenPort ? 50722,
  allowedIPs ? ["10.0.0.0/24"],
  persistentKeepalive ? 25,
}: let
  # Extract a single `Field = value` line from the conf into its own file.
  keyFile = label: field:
    pkgs.runCommandLocal "${name}-${label}" {} ''
      ${pkgs.gnused}/bin/sed -n 's/^${field}[[:space:]]*=[[:space:]]*//p' ${conf} \
        | ${pkgs.coreutils}/bin/head -n1 \
        | ${pkgs.coreutils}/bin/tr -d '[:space:]' > "$out"
    '';
in {
  netdev = {
    netdevConfig = {
      Kind = "wireguard";
      Name = name;
    };
    wireguardConfig = {
      PrivateKeyFile = keyFile "privatekey" "PrivateKey";
      ListenPort = listenPort;
    };
    wireguardPeers = [
      {
        PublicKey = serverPublicKey;
        PresharedKeyFile = keyFile "presharedkey" "PresharedKey";
        AllowedIPs = allowedIPs;
        Endpoint = endpoint;
        PersistentKeepalive = persistentKeepalive;
      }
    ];
  };
  network = {
    matchConfig.Name = name;
    address = [address];
  };
}
