{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "aarch64-linux";
  kind = "nixos";
  roles = ["server"];

  profiles = with nixosProfiles; [
    base
    server
  ];

  modules = [
    ./system.nix
  ];

  users = {
    nix = {
      home = {
        profiles = with homeProfiles; [
          core
        ];
        modules = [
          userModules.nix.module
        ];
      };
    };

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
