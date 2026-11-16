# The nixpkgs a platform builds from. Each channel only waits for its own
# platform on Hydra: nixos-26.05 for Linux builds and NixOS tests,
# nixpkgs-26.05-darwin for darwin builds. So darwin follows the darwin one,
# whose commits Hydra has finished building for darwin
# (docs/decisions.md#nixpkgs-darwin).
# Darwin systems get it through nix-darwin's follows in flake.nix instead.
inputs: system:
if inputs.nixpkgs.lib.hasSuffix "-darwin" system
then inputs.nixpkgs-darwin
else inputs.nixpkgs
