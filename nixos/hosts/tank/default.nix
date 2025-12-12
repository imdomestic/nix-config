{ inputs }:
let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix { inherit inputs; };
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["desktop" "gui" "server"];
  ip = "10.0.0.66";
  sshUser = "root";

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
    inputs.vscode-server.nixosModules.default
    inputs.chaotic.nixosModules.default
    inputs.daeuniverse.nixosModules.dae
    inputs.daeuniverse.nixosModules.daed
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
    fendada = {
      home = {
        profiles = with homeProfiles; [
          core
          gui.linux
        ];
        modules = [
          userModules.fendada.module
        ];
      };
    };
    linwhite = {
      home = {
        profiles = with homeProfiles; [
          core
          gui.linux
        ];
        modules = [
          userModules.linwhite.module
        ];
      };
    };
    genisys = {
      home = {
        profiles = with homeProfiles; [
          core
          gui.linux
        ];
        modules = [
          userModules.genisys.module
        ];
      };
    };
  };
}
