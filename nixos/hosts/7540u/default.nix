{ inputs }:
let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix { inherit inputs; };
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["desktop" "gui"];

  profiles = with nixosProfiles; [
    base
    desktop
    virtualisation
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
  ];

  externalModules = [
    inputs.nixos-hardware.nixosModules.lenovo-thinkpad-t14s-amd-gen4
    inputs.daeuniverse.nixosModules.dae
    inputs.daeuniverse.nixosModules.daed
    inputs.catppuccin.nixosModules.catppuccin
    inputs.vscode-server.nixosModules.default
    inputs.chaotic.nixosModules.default
    inputs.niri.nixosModules.niri
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
