{
  lib,
  config,
  inputs,
  ...
}: let
  registryPins = import ../../lib/nixpkgs-registry.nix {inherit inputs;};
in {
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
}
