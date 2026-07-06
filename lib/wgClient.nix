# Build a systemd-networkd WireGuard *client* interface.
#
# Preferred mode — key files provisioned at runtime (sops-nix):
#   let
#     wg = import ../../../lib/wgClient.nix { inherit pkgs; } {
#       privateKeyFile = config.sops.secrets."wireguard/private_key".path;
#       presharedKeyFile = config.sops.secrets."wireguard/preshared_key".path;
#       address = "10.0.0.66/24";
#     };
#   in {
#     systemd.network.netdevs."40-wg0" = wg.netdev;
#     systemd.network.networks."40-wg0" = wg.network;
#   }
#   (declare the two sops.secrets with owner = "systemd-network")
#
# Legacy mode — extract keys from a wg-quick conf in the private `wg-config`
# input. NOTE: the extracted key files land in the world-readable nix store;
# migrate hosts to the sops mode above as their host keys get onboarded.
{pkgs}: {
  address,
  conf ? null,
  privateKeyFile ? null,
  presharedKeyFile ? null,
  name ? "wg0",
  serverPublicKey ? "i9ZU3WdqNxUyqtaM9F8Rbrs4ophdNpQ6wZeO/bV/jjQ=",
  endpoint ? "sh.imdomestic.com:50722",
  listenPort ? 50722,
  allowedIPs ? ["10.0.0.0/24"],
  persistentKeepalive ? 25,
}: let
  # Legacy: extract a single `Field = value` line from the conf into its own file.
  keyFile = label: field:
    pkgs.runCommandLocal "${name}-${label}" {} ''
      ${pkgs.gnused}/bin/sed -n 's/^${field}[[:space:]]*=[[:space:]]*//p' ${conf} \
        | ${pkgs.coreutils}/bin/head -n1 \
        | ${pkgs.coreutils}/bin/tr -d '[:space:]' > "$out"
    '';
  privateKey =
    if privateKeyFile != null
    then privateKeyFile
    else if conf != null
    then keyFile "privatekey" "PrivateKey"
    else throw "wgClient: set privateKeyFile (sops) or conf (legacy)";
  presharedKey =
    if presharedKeyFile != null
    then presharedKeyFile
    else if conf != null
    then keyFile "presharedkey" "PresharedKey"
    else throw "wgClient: set presharedKeyFile (sops) or conf (legacy)";
in {
  netdev = {
    netdevConfig = {
      Kind = "wireguard";
      Name = name;
    };
    wireguardConfig = {
      PrivateKeyFile = privateKey;
      ListenPort = listenPort;
    };
    wireguardPeers = [
      {
        PublicKey = serverPublicKey;
        PresharedKeyFile = presharedKey;
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
