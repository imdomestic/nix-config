{ inputs }:
let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix { inherit inputs; };
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["desktop" "gui"];

  profiles = with nixosProfiles; [
    base
    desktop
    virtualisation
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
  ];

  externalModules = [
    inputs.daeuniverse.nixosModules.dae
    inputs.daeuniverse.nixosModules.daed
    inputs.vscode-server.nixosModules.default
    inputs.steam-servers.nixosModules.default
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
    genisys = {
      home = {
        profiles = with homeProfiles; [
          core
          dev
          gui.linux
        ];
        modules = [
          userModules.genisys.module
        ];
      };
    };
  };
}
