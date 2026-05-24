{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["cli" "gui"];

  profiles = with nixosProfiles; [
    base
  ];

  modules = [
    ./system.nix
  ];

  externalModules = [
    inputs.nixos-wsl.nixosModules.wsl
    inputs.nix-index-database.nixosModules.default
  ];

  users = {
    linwhite = {
      home = {
        profiles = with homeProfiles; [
          core
          base
          dev
          gui.linux
        ];
        modules = [
          userModules.linwhite.module
        ];
      };
    };
  };
}
