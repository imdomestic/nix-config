{
  config,
  inputs,
  ...
}: let
  m = config.flake.modules;
in {
  hosts.encore = {
    system = "x86_64-linux";
    kind = "nixos";
    roles = ["server" "gpu-compute" "desktop" "gui"];
    tsName = "encore.inner.imdomestic.com";

    profiles = with m.nixos; [
      base
      server
    ];

    modules = [
      ./system.nix
      m.nixos.sudo-pwfeedback
      ./cooling.nix
      ./keyboard.nix
      ./retained-services.nix
      ./hardware-configuration.nix
      m.nixos.linwhite-smb
      m.nixos.vex
      ./vex.nix
    ];

    externalModules = [
      inputs.nixos-hardware.nixosModules.asus-zephyrus-gu603h
      inputs.nix-index-database.nixosModules.default
    ];

    users = {
      hank = {};
      linwhite.gui.profile = m.homeManager.gui-common;
    };
  };
}
