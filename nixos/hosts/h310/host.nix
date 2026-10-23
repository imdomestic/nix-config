{config, ...}: let
  m = config.flake.modules;
in {
  hosts.h310 = {
    system = "x86_64-linux";
    kind = "nixos";
    roles = ["server"];
    tsName = "h310.inner.imdomestic.com";
    clusterControl = {
      enable = true;
      manageableUnits = ["tailscaled.service" "prometheus-node-exporter.service" "gaoji-cluster-worker.service"];
    };
    maxTier = "interactive";

    profiles = with m.nixos; [
      base
      server
    ];

    modules = [
      ./system.nix
      ./hardware-configuration.nix
      m.nixos.gaoji-worker
    ];

    users = {
      hank = {};
      kenneth = {};
      fendada = {};
      linwhite = {};
    };
  };
}
