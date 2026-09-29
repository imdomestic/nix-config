{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["desktop" "gui"];

  profiles = with nixosProfiles; [base];
  modules = [
    ./system.nix
    ./hardware-configuration.nix
    ./desktop.nix
  ];
  hardwareModules = [inputs.nixos-hardware.nixosModules.lenovo-yoga-7-14ILL10];
  externalModules = [inputs.nix-index-database.nixosModules.default];

  users.hank.home = {
    profiles = with homeProfiles; [core base interactive];
    modules = [
      userModules.hank.module
      userModules.hank.dev
      ../../../home/users/hank/gnome.nix
      ../../../home/modules/ibus
    ];
  };
}
