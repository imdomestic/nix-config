# What every standalone home starts with, below any tier: the plumbing
# flake/builders/homes.nix needs, nothing an account would choose.
{
  lib,
  config,
  inputs,
  ...
}: let
  registryPins = import ../../lib/nixpkgs-registry.nix {inherit inputs;};
in {
  options.my.home.tier = lib.mkOption {
    type = (import ./tiers.nix {inherit lib;}).type;
    readOnly = true;
    description = "This home's tier on this host (./tiers.nix), set by flake/builders/homes.nix.";
  };

  config = {
    # ~/.config/nix/registry.json, the user tier — the only one that exists on
    # machines where Nix came from the upstream installer and nothing declarative
    # owns /etc. Where a system tier is also pinned this just restates it.
    nix.registry = registryPins.registry;

    home = {
      homeDirectory =
        if lib.hasInfix "darwin" config.my.host.system
        then "/Users/${config.home.username}"
        else "/home/${config.home.username}";
      stateVersion = "26.05";
    };
    programs.home-manager.enable = true;
  };
}
