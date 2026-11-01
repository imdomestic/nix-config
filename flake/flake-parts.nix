{
  # perSystem is unused; flake-parts still needs the list. These are the systems
  # `packages` (./outputs/packages.nix) and `formatter` (./outputs/misc.nix) cover.
  config.systems = ["x86_64-linux" "aarch64-linux" "aarch64-darwin"];
}
