{
  config,
  lib,
  ...
}: let
  services = config.my.tailscale.guardedTCPServices;
  ports = lib.unique (lib.concatLists (lib.attrValues services));
in {
  options.my.tailscale.guardedTCPServices = lib.mkOption {
    type = lib.types.attrsOf (lib.types.listOf lib.types.port);
    default = {};
    description = "Wildcard listeners needed before MagicDNS: unit name to private TCP ports. Access is limited to lo and tailscale0 independently of the general firewall.";
  };
  config = lib.mkIf (ports != []) {
    networking.nftables.enable = true;
    networking.nftables.tables.tailnet-services = {
      family = "inet";
      content = ''
        chain input {
          type filter hook input priority -10; policy accept;
          iifname != { "lo", "tailscale0" } tcp dport { ${lib.concatMapStringsSep ", " toString ports} } counter drop
        }
      '';
    };
    systemd.services =
      lib.mapAttrs (_: _: {
        after = ["nftables.service"];
        bindsTo = ["nftables.service"];
        partOf = ["nftables.service"];
      })
      services;
  };
}
