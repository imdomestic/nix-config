# Build a systemd-networkd WireGuard *server* interface.
#
# Preferred mode — peer list from the repo, keys provisioned at runtime (sops-nix):
#   let
#     wg = import ../../../lib/wgServer.nix { inherit pkgs lib; } {
#       peers = import ./wg-peers.nix;
#       privateKeyFile = config.sops.secrets."wireguard/private_key".path;
#       pskFileFor = idx: config.sops.secrets."wireguard/psk/${toString idx}".path;
#       address = "10.0.0.1/24";
#     };
#   in {
#     systemd.network.netdevs."40-wg0" = wg.netdev;
#     systemd.network.networks."40-wg0" = wg.network;
#   }
#   (declare the sops.secrets with owner = "systemd-network"; psk index order
#    must match the peers list, see nixos/hosts/shanghai/wg-peers.nix)
#
# Legacy mode — parse a wg-quick style server conf from the private `wg-config`
# input. NOTE: the extracted key files land in the world-readable nix store.
#
# NAT (the conf's `PostUp` iptables MASQUERADE) is intentionally *not* handled
# here; replicate it in the host via nftables / networkConfig.IPMasquerade.
{
  pkgs,
  lib,
}: {
  conf ? null,
  peers ? null,
  privateKeyFile ? null,
  pskFileFor ? null,
  address ? "10.0.0.1/24",
  name ? "wg0",
  listenPort ? 50722,
}: let
  useConf = conf != null;

  lines =
    if useConf
    then lib.splitString "\n" (builtins.readFile conf)
    else [];

  # Collect every `Field = value` value across the conf, in file order.
  collect = field:
    lib.filter (x: x != null) (map (l: let
      m = builtins.match "${field} = (.*)" l;
    in
      if m == null
      then null
      else lib.head m)
    lines);

  confPrivateKeyFile =
    pkgs.runCommandLocal "${name}-privatekey" {} ''
      ${pkgs.gnused}/bin/sed -n 's/^PrivateKey[[:space:]]*=[[:space:]]*//p' ${conf} \
        | ${pkgs.coreutils}/bin/head -n1 \
        | ${pkgs.coreutils}/bin/tr -d '[:space:]' > "$out"
    '';

  # Nth (0-based) PresharedKey, matching the Nth [Peer] block in file order.
  confPskFile = idx:
    pkgs.runCommandLocal "${name}-psk-${toString idx}" {} ''
      ${pkgs.gawk}/bin/awk -F ' = ' '
        /^PresharedKey/ { c++; if (c == ${toString (idx + 1)}) { printf "%s", $2; exit } }
      ' ${conf} > "$out"
    '';

  peerList =
    if useConf
    then
      lib.imap0 (idx: pub: {
        publicKey = pub;
        allowedIPs = [(lib.elemAt (collect "AllowedIPs") idx)];
      }) (collect "PublicKey")
    else
      if peers == null
      then throw "wgServer: set peers + privateKeyFile + pskFileFor (sops) or conf (legacy)"
      else peers;

  pskFile =
    if useConf
    then confPskFile
    else pskFileFor;

  wireguardPeers =
    lib.imap0 (idx: peer: {
      PublicKey = peer.publicKey;
      PresharedKeyFile = pskFile idx;
      AllowedIPs = peer.allowedIPs;
    })
    peerList;
in {
  netdev = {
    netdevConfig = {
      Kind = "wireguard";
      Name = name;
    };
    wireguardConfig = {
      PrivateKeyFile =
        if useConf
        then confPrivateKeyFile
        else privateKeyFile;
      ListenPort = listenPort;
    };
    inherit wireguardPeers;
  };
  network = {
    matchConfig.Name = name;
    address = [address];
  };
}
