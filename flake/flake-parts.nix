{
  # perSystem is unused; flake-parts still needs the list. These are the systems
  # `packages` covers (./outputs/packages.nix).
  config.systems = ["x86_64-linux" "aarch64-linux" "aarch64-darwin"];
}
