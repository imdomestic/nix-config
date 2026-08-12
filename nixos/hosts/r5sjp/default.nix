{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "aarch64-linux";
  kind = "nixos";
  roles = ["server"];
  tsIp = "100.64.0.16";

  profiles = with nixosProfiles; [
    base
    server
    netdiag
  ];

  modules = [
    ./system.nix
  ];

  users = {
    nix = {
      home = {
        profiles = with homeProfiles; [
          core
        ];
        modules = [
          userModules.nix.module
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
  };
}
