{lib, ...}: {
  # Modules picked by name: `flake.modules.<class>.<name>` (./modules/*.nix and
  # home/users/*/user.nix). Unlike flake-parts' own `flake.modules`
  # (flakeModules.modules) the values stay as given, with no class-tagging
  # wrapper: the module system orders definitions by import depth, so every
  # extra `imports` layer reorders list options like `environment.systemPackages`
  # and `home.packages` — and with buildEnv's ignoreCollisions, order decides
  # which package wins a colliding file.
  options.flake.modules = lib.mkOption {
    type = lib.types.lazyAttrsOf (lib.types.lazyAttrsOf lib.types.raw);
    default = {};
    description = "System modules by class (nixos, darwin, systemManager) and name.";
  };

  # perSystem is unused; flake-parts still needs the list. These are the systems
  # `packages` covers (./outputs/packages.nix).
  config.systems = ["x86_64-linux" "aarch64-linux" "aarch64-darwin"];
}
