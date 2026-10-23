{config, ...}: let
  m = config.flake.modules;
in {
  hosts.gizmo = {
    system = "aarch64-linux";
    kind = "nixos";
    roles = ["server"];
    tsName = "gizmo.inner.imdomestic.com";
    # 这台不是该段的网关,只是段里的 DHCP 客户端;回程靠 tailscale 默认的 SNAT。
    lanRoutes = ["10.1.2.0/24"];
    clusterControl = {
      enable = true;
      manageableUnits = ["tailscaled.service" "prometheus-node-exporter.service" "xray.service" "nginx.service" "ddns-go.service" "systemd-resolved.service"];
    };
    maxTier = "interactive";
    buildOn = "r6s";

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
      linwhite = {};
      hank = {};
    };
  };
}
