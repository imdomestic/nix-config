{config, ...}: let
  m = config.flake.modules;
in {
  hosts.r2s = {
    system = "aarch64-linux";
    kind = "nixos";
    roles = ["server"];
    tsName = "r2s.inner.imdomestic.com";
    lanRoutes = ["192.168.4.0/24"];
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

    users.hank = {};
  };
}
