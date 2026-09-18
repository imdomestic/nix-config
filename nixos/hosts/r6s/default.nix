{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "aarch64-linux";
  kind = "nixos";
  roles = ["server"];
  tsName = "r6s.inner.imdomestic.com";
  lanRoutes = ["192.168.22.0/24"];
  clusterControl = {
    enable = true;
    manageableUnits = ["tailscaled.service" "prometheus-node-exporter.service" "xray.service" "mihomo.service" "ddns-go.service" "systemd-resolved.service"];
  };
  ip = "10.0.0.4";
  sshUser = "root";

  profiles = with nixosProfiles; [
    base
    server
    netdiag
    # desktop
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
  ];

  externalModules = [
    # inputs.determinate.nixosModule.default
  ];

  users = {
    hank = {
      home = {
        profiles = with homeProfiles; [
          core
          base
          interactive
        ];
        modules = [
          userModules.hank.module
        ];
      };
    };
  };
}
