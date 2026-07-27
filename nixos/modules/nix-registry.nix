# Pins the indirect `nixpkgs` flake refs, through whichever sink the host
# actually has. See lib/nixpkgs-registry.nix for what the pins are and why.
#
#   nix.registry              NixOS, and nix-darwin hosts that still manage Nix
#   determinateNix.registry   hosts that handed Nix to Determinate
#   /etc/nix/registry.json    everything else — system-manager, and any darwin
#                             host with `nix.enable = false` and no Determinate
#                             module to pick up the slack
#
# Note the `lib.optional`s: a definition inside a false `mkIf` is still a
# definition as far as the "option does not exist" check goes, so options that
# only exist on some platforms have to be guarded structurally.
{
  inputs,
  config,
  options,
  lib,
  ...
}: let
  pins = import ../../lib/nixpkgs-registry.nix {inherit inputs;};

  viaDeterminate = options ? determinateNix && config.determinateNix.enable;
in {
  config = lib.mkMerge (
    lib.optional (options.nix ? registry) (
      lib.mkIf config.nix.enable {nix.registry = pins.registry;}
    )
    ++ lib.optional (options ? determinateNix) (
      lib.mkIf config.determinateNix.enable {determinateNix.registry = pins.registry;}
    )
    ++ [
      # /etc/nix/registry.json is a hardcoded path in Nix, read as the system
      # tier above the global registry — it needs no nix.conf setting to take
      # effect. Both sinks above end up writing this same file, hence the guard.
      (lib.mkIf (!config.nix.enable && !viaDeterminate) {
        environment.etc."nix/registry.json".text = pins.etcJSON;
      })
    ]
  );
}
