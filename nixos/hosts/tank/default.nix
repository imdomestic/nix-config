{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["server"];
  ip = "10.0.0.66";
  sshUser = "root";

  profiles = with nixosProfiles; [
    base
    server
    # desktop
    virtualisation
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
  ];

  externalModules = [
    # inputs.vscode-server.nixosModules.default
    inputs.nix-minecraft.nixosModules.minecraft-servers
    inputs.nix-index-database.nixosModules.default
  ];

  users = {
    hank = {
      home = {
        profiles = with homeProfiles; [
          core
          base
          # gui.linux
        ];
        modules = [
          userModules.hank.module
          userModules.hank.dev
        ];
      };
    };
    fendada = {
      home = {
        profiles = with homeProfiles; [
          core
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
        ];
        modules = [
          userModules.genisys.module
        ];
      };
    };
  };
}
