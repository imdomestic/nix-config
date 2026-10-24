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
    ageKey = "age1f6suumsw5f3e5sqf46j63kmympqk0anexjvuwsg7uh02wxnkwymqmkj32v";

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
      hank = {
        ageKey = "age1wh7zpq8aaqx5anad9nxk9cr40q0rq2qcnsrpujmrmsf8z59aycsqhlpmth";
        modules = [m.homeManager.hank-encore];
      };
      linwhite = {
        gui.profile = m.homeManager.gui-common;
        modules = [m.homeManager.linwhite-encore];
        ageKey = "age1kmgn6snvphehfluadsztazkvlj5q8u6rydzm3at0y3muu45ny43szct0qr";
      };
    };
  };
}
