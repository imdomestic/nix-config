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
  roles = import ../_lib/roles.nix;

  # Profiles come in this order whatever order a host lists its roles in.
  # Module order is definition order for list options (systemPackages…), so it
  # is fixed here rather than taken from attrNames, which sorts.
  profileOrder = ["server" "desktop" "router" "vm-host"];
  base = {
    nixos = ../../system/profiles/base.nix;
    darwin = ../../system/profiles/darwin.nix;
  };
  profilesOf = host:
    lib.throwIfNot (lib.all (r: roles.${r} ? profiles -> lib.elem r profileOrder) (lib.attrNames roles))
    "flake/_lib/roles.nix: every role with profiles must be in profileOrder (flake/builders/systems.nix)"
    ([base.${host.kind}]
      ++ lib.concatMap (r: roles.${r}.profiles.${host.kind} or [])
      (lib.filter (r: lib.elem r host.roles) profileOrder));

  # The host's own files that load by name, ahead of whatever host.nix lists.
  byName = host: n: let
    f = host.dir + "/${n}.nix";
  in
    lib.optional (builtins.pathExists f) f;

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
        ++ lib.unique (profilesOf host
          ++ byName host "system"
          ++ byName host "hardware-configuration"
          ++ host.modules
          ++ host.hardwareModules
          ++ host.externalModules);
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
        modules = [../../system/installers/x86_64-rescue.nix];
      };
    };
  flake.darwinConfigurations = ofKind "darwin";
}
