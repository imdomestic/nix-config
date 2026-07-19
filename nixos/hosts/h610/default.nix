{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["server"];
  ip = "10.0.0.5";
  sshUser = "root";

  profiles = with nixosProfiles; [
    base
    server
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
  ];

  externalModules = [
    # inputs.headplane.nixosModules.headplane
    inputs.max.nixosModules.max-bot
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
          userModules.hank.dev
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
    linwhite = {
      home = {
        profiles = with homeProfiles; [
          core
          base
        ];
        modules = [
          userModules.linwhite.module
        ];
      };
    };
    kenneth = {
      home = {
        profiles = with homeProfiles; [
          core
          base
        ];
        modules = [
          userModules.kenneth.module
        ];
      };
    };
    fendada = {
      home = {
        profiles = with homeProfiles; [
          core
          base
        ];
        modules = [
          userModules.fendada.module
        ];
      };
    };
  };
}
