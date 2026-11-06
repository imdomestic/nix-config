# nixosConfigurations / darwinConfigurations, one per registry entry of that
# kind. No home-manager module here on purpose: homes are standalone
# `homeConfigurations` (./homes.nix) on every host, so `nixos-rebuild switch`
# never rebuilds a user's home and a user can re-activate their own without
# touching the machine.
{
  config,
  inputs,
  lib,
  ...
}: let
  systemModules = import ../_lib/system-modules.nix {inherit config inputs lib;};

  mkSystem = hostName: host: let
    builder =
      if host.kind == "darwin"
      then inputs.nix-darwin.lib.darwinSystem
      else inputs.nixpkgs.lib.nixosSystem;
  in
    builder ({inherit (host) system;} // systemModules {inherit hostName;});

  ofKind = kind: lib.mapAttrs mkSystem (lib.filterAttrs (_: h: h.kind == kind) config.hosts);
in {
  flake.nixosConfigurations =
    ofKind "nixos"
    // {
      x86_64-rescue = inputs.nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [../../system/installers/x86_64-rescue.nix];
      };
    };
  flake.darwinConfigurations = ofKind "darwin";
}
