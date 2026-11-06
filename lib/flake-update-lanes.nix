# The flake inputs tank's nightly updater moves, in this order
# (system/modules/flake-updater, docs/decisions.md#flake-updater). An input
# missing from both lists is moved by hand: our own repositories, inputs
# pinned to a tag or commit, and llm-agents, which has its own hourly workflow.
{
  # Release branches: their maintainers promise no breaking changes.
  release = [
    "nixpkgs"
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
    "nix-minecraft"
    "NixVirt"
    "zjstatus"
    "paneru"
  ];
}
