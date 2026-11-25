# The flake inputs tank's nightly updater moves, in this order
# (system/modules/flake-updater, docs/decisions.md#flake-updater). An input
# missing from these lists is moved by hand: our other repositories, inputs
# pinned to a tag or commit, and llm-agents, which has its own hourly workflow.
{
  # Release branches: their maintainers promise no breaking changes.
  release = [
    "nixpkgs"
    "nixpkgs-darwin"
    "home-manager"
    "nix-darwin"
    "nixvim"
    "system-manager"
  ];
  # Third-party branches with no such promise.
  rolling = [
    "nixpkgs-unstable"
    "nixos-hardware"
    "sops-nix"
    "disko"
    "deploy-rs"
    "determinate"
    "nur"
    "nix-index-database"
    "nixos-wsl"
    "flake-parts"
    "import-tree"
    "nixidy"
    "NixVirt"
    "zjstatus"
  ];
  # Our own, whose main is only what its own checks passed. Last, so it is
  # built and VM-tested with the night's nixpkgs
  # (docs/decisions.md#maxx-moves-nightly).
  own = [
    "maxx"
  ];
}
