{config, ...}: let
  m = config.flake.modules;
in {
  hosts.r5s = {
    system = "aarch64-linux";
    kind = "nixos";
    roles = ["server"];
    tsName = "r5s.inner.imdomestic.com";
    # tank 那一段;tank 的救援 initrd 也在这段上(192.168.20.50)。
    lanRoutes = ["192.168.20.0/24"];
    clusterControl = {
      enable = true;
      manageableUnits = ["tailscaled.service" "prometheus-node-exporter.service" "xray.service" "mihomo.service" "ddns-go.service" "systemd-resolved.service"];
    };
    ip = "10.0.0.9";
    sshUser = "root";
    maxTier = "interactive";

    profiles = with m.nixos; [
      base
      server
      netdiag
    ];

    modules = [
      ./system.nix
    ];

    users = {
      nix = {};
      hank = {};
    };
  };
}
