{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["server"];
  tsIp = "100.64.0.30";

  profiles = with nixosProfiles; [
    base
    server
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
  ];

  users = {
    hank.home = {
      profiles = with homeProfiles; [
        core
        base
      ];
      modules = [
        userModules.hank.module
      ];
    };

    kenneth.home = {
      profiles = with homeProfiles; [
        core
        base
      ];
      modules = [
        userModules.kenneth.module
      ];
    };

    fendada.home = {
      profiles = with homeProfiles; [
        core
        base
      ];
      modules = [
        userModules.fendada.module
      ];
    };

    linwhite.home = {
      profiles = with homeProfiles; [
        core
        base
      ];
      modules = [
        userModules.linwhite.module
      ];
    };
  };
}
