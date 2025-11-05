{ inputs }:
let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix { inherit inputs; };
in {
  system = "aarch64-linux";
  kind = "nixos";
  roles = ["desktop" "gui"];

  profiles = with nixosProfiles; [
    base
    desktop
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
  ];

  users = {
    hank = {
      home = {
        profiles = with homeProfiles; [
          core
          dev
          gui.linux
        ];
        modules = [
          userModules.hank.module
        ];
      };
    };
    nix = {
      home = {
        profiles = with homeProfiles; [
          core
          gui.linux
        ];
        modules = [
          userModules.nix.module
        ];
      };
    };
  };
}
