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
  hostModules = import ../_lib/host-modules.nix {inherit config lib;};

  mkSystem = hostName: host: let
    builder =
      if host.kind == "darwin"
      then inputs.nix-darwin.lib.darwinSystem
      else inputs.nixpkgs.lib.nixosSystem;
  in
    builder {
      inherit (host) system;
      modules =
        hostModules hostName
        ++ lib.unique (host.profiles ++ host.modules ++ host.hardwareModules ++ host.externalModules);
      # `system` and `inputs` stay specialArgs because base profiles use them
      # in `imports`, which cannot depend on config. Everything else lives in
      # `config.my.host`.
      specialArgs = {
        inherit inputs;
        inherit (host) system;
        "pkgs-unstable" = import inputs.nixpkgs-unstable {
          inherit (host) system;
          overlays = [inputs.nur.overlays.default];
          config = import ../_lib/nixpkgs-config.nix;
        };
      };
    };

  ofKind = kind: lib.mapAttrs mkSystem (lib.filterAttrs (_: h: h.kind == kind) config.hosts);
in {
  flake.nixosConfigurations =
    ofKind "nixos"
    // {
      x86_64-rescue = inputs.nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [../../nixos/installers/x86_64-rescue.nix];
      };
    };
  flake.darwinConfigurations = ofKind "darwin";
}
