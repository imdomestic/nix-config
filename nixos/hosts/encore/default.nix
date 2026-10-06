{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["server" "gpu-compute" "desktop" "gui"];
  tsName = "encore.inner.imdomestic.com";

  profiles = with nixosProfiles; [
    base
    server
  ];

  modules = [
    ./system.nix
    ./minecraft.nix
    ./hardware-configuration.nix
    ../../modules/linwhite-smb.nix
  ];

  externalModules = [
    inputs.nix-minecraft.nixosModules.minecraft-servers
    inputs.nixos-hardware.nixosModules.asus-zephyrus-gu603h
    inputs.nix-index-database.nixosModules.default
  ];

  users = {
    hank.home = {
      profiles = with homeProfiles; [
        core
        base
        interactive
      ];
      modules = [
        userModules.hank.module
        userModules.hank.dev
        ../../../home/users/hank/gnome.nix
        ../../../home/modules/ibus
      ];
    };
    linwhite = {
      home = {
        profiles = with homeProfiles; [
          core
          base
          interactive
          gui.common
        ];
        modules = [
          userModules.linwhite.module
          userModules.linwhite.dev
        ];
      };
    };
  };
}
