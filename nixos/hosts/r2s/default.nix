{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "aarch64-linux";
  kind = "nixos";
  roles = ["server"];
  tsName = "r2s.inner.imdomestic.com";
  lanRoutes = ["192.168.4.0/24"];

  profiles = with nixosProfiles; [
    base
    server
    netdiag
  ];

  modules = [
    ./system.nix
  ];

  users = {
    hank = {
      home = {
        profiles = with homeProfiles; [
          core
          base
        ];
        modules = [
          userModules.hank.module
        ];
      };
    };
  };
}
