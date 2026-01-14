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
  ];

  externalModules = [
    inputs.nixos-wsl.nixosModules.default
    inputs.nix-index-database.nixosModules.default
    # inputs.daeuniverse.nixosModules.dae
    # inputs.daeuniverse.nixosModules.daed
    # inputs.niri.nixosModules.niri
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
