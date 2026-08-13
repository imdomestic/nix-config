{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "aarch64-linux";
  kind = "nixos";
  roles = ["server"];
  sshUser = "hank";
  # tsIp = "100.64.0.9";

  profiles = with nixosProfiles; [
    base
    server
  ];

  modules = [
    ./system.nix
  ];

  users.hank = {
    extraGroups = ["wheel"];
    nixos = {
      linger = true;
      openssh.authorizedKeys.keys = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILUdWAJA+GYaOtVHVkrvrEpwGpK//0hYdAYjYq/rzvtn ysh2291939848@outlook.com"
      ];
    };

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
}
