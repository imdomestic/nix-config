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
    # desktop
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
  ];

  externalModules = [
    inputs.nixos-hardware.nixosModules.raspberry-pi-4
    # inputs.niri.nixosModules.niri
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
    # nix = {
    #   home = {
    #     profiles = with homeProfiles; [
    #       core
    #       gui.linux
    #     ];
    #     modules = [
    #       userModules.nix.module
    #     ];
    #   };
    # };
  };
}
