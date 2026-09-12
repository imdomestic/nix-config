{
  inputs,
  pkgs,
}: let
  package = import (inputs.qq-bot + "/nix/ops-compat-package.nix") {
    inherit pkgs;
    package = inputs.maxops.packages.${pkgs.stdenv.hostPlatform.system}.default;
  };
  # Preserve the consumer patch while matching maxops' new schema descriptions.
  refreshContext = patch: let
    source = builtins.readFile patch;
    before = [
      "@@ -100,12 +100,27 @@"
      " pub struct WorkspaceCreateParams {\n     pub repository: String,\n     #[serde(default)]"
    ];
    after = [
      "@@ -100,14 +100,29 @@"
      " pub struct WorkspaceCreateParams {\n     /// Permitted repository name from resources.list(kind=repositories).\n     pub repository: String,\n     /// Expected full remote commit hash observed for the configured ref; a later external push rejects this operation instead of being overwritten.\n     #[serde(default)]"
    ];
  in
    assert builtins.all (context: pkgs.lib.hasInfix context source) before;
      pkgs.writeText "ops-exact-source.patch" (builtins.replaceStrings before after source);
in
  package.overrideAttrs (old: {
    patches = map (patch:
      if baseNameOf patch == "ops-exact-source.patch"
      then refreshContext patch
      else patch)
    old.patches;
  })
