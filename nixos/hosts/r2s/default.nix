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
    hank = {
      home = {
        profiles = with homeProfiles; [
          core
          dev
        ];
        modules = [
          userModules.hank.module
        ];
      };
    };
  };
}
