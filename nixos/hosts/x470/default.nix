{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["desktop" "gui" "server"];
  ip = "10.0.0.77";
  sshUser = "root";

  profiles = with nixosProfiles; [
    base
    desktop
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
  ];

  externalModules = [
    inputs.vscode-server.nixosModules.default
    inputs.nix-minecraft.nixosModules.minecraft-servers
    inputs.determinate.nixosModules.default
  ];

  users = {
    hank = {
      home = {
        profiles = with homeProfiles; [
          core
          base
          dev
          gui.linux
        ];
        modules = [
          userModules.hank.module
        ];
      };
    };
  };
}
