{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["cli"];

  profiles = with nixosProfiles; [
    base
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
          dev
        ];
        modules = [
          userModules.hank.module
        ];
      };
    };
  };
}
