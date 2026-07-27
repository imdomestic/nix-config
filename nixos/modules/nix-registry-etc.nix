{
  inputs,
  lib,
  config,
  ...
}: let
  registryPins = import ../../lib/nixpkgs-registry.nix {inherit inputs;};

  # Only the platforms that have no usable `nix.registry`:
  #   - nix-darwin hosts running Determinate Nix, where `nix.enable = false`
  #     drops the whole nix module (registry.json included) on the floor.
  #   - system-manager, whose nix module only ships `enable` and `package`.
  # Hosts that *do* manage it (nix.enable, or determinateNix.registry) already
  # write this same file, so claiming it here would collide.
  unmanaged = !config.nix.enable && !(config.determinateNix.enable or false);
in {
  # /etc/nix/registry.json is a hardcoded path in Nix, read as the system tier
  # above the global registry — it needs no nix.conf setting to take effect.
  environment.etc."nix/registry.json" =
    lib.mkIf unmanaged {text = registryPins.etcJSON;};
}
