{ inputs }:
let
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix { inherit inputs; };
in {
  system = "aarch64-linux";
  kind = "home";
  roles = ["server"];

  users = {
    hank = {
      home = {
        profiles = with homeProfiles; [
          core
          dev
        ];
        modules = [
          userModules.hank.module
        ];
      };
    };
  };
}
