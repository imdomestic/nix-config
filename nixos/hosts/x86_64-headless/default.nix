{ inputs }:
let
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix { inherit inputs; };
in {
  system = "x86_64-linux";
  kind = "home";
  roles = ["server"];

  systemManager = {
    enable = true;
    modules = [
      ../../modules/nix.nix
      ./system-manager.nix
    ];
  };

  externalModules = [
    # inputs.niri.nixosModules.niri
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
  };
}

