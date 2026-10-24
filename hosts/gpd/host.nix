{config, ...}: let
  m = config.flake.modules;
in {
  hosts.gpd = {
    system = "x86_64-linux";
    kind = "nixos";
    roles = ["desktop" "gui"];

    modules = [
      ./system.nix
      m.nixos.sudo-pwfeedback
      ./hardware-configuration.nix
    ];

    users.linwhite.modules = [m.homeManager.linwhite-gpd];
  };
}
