{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["server"];
  tsName = "h310.inner.imdomestic.com";
  clusterControl = {
    enable = true;
    manageableUnits = ["tailscaled.service" "prometheus-node-exporter.service" "gaoji-cluster-worker.service"];
  };

  profiles = with nixosProfiles; [
    base
    server
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
    ../../modules/gaoji-worker.nix
  ];

  users = {
    hank.home = {
      profiles = with homeProfiles; [
        core
        base
        interactive
      ];
      modules = [
        userModules.hank.module
      ];
    };

    kenneth.home = {
      profiles = with homeProfiles; [
        core
        base
        interactive
      ];
      modules = [
        userModules.kenneth.module
      ];
    };

    fendada.home = {
      profiles = with homeProfiles; [
        core
        base
        interactive
      ];
      modules = [
        userModules.fendada.module
      ];
    };

    linwhite.home = {
      profiles = with homeProfiles; [
        core
        base
        interactive
      ];
      modules = [
        userModules.linwhite.module
      ];
    };
  };
}
