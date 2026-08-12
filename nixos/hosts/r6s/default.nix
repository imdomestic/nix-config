{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "aarch64-linux";
  kind = "nixos";
  roles = ["server"];
  tsIp = "100.64.0.5";
  ip = "10.0.0.4";
  sshUser = "root";

  profiles = with nixosProfiles; [
    base
    server
    netdiag
    # desktop
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
  ];

  externalModules = [
    # inputs.niri.nixosModules.niri
    # inputs.determinate.nixosModule.default
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
  };
}
