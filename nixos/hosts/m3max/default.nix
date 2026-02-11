{inputs}: let
  darwinProfiles = import ../../../darwin/profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "aarch64-darwin";
  kind = "darwin";
  roles = ["desktop" "gui"];

  profiles = with darwinProfiles; [
    base
  ];

  modules = [
    ./system.nix
  ];

  users = {
    hank = {
      home = {
        profiles = with homeProfiles; [
          core
          base
          dev
          gui.darwin
        ];
        modules = [
          userModules.hank.module
        ];
      };
    };
  };
}
