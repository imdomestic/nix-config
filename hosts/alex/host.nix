{
  config,
  inputs,
  ...
}: let
  m = config.flake.modules;
in {
  hosts.alex = {
    system = "aarch64-darwin";
    kind = "darwin";
    roles = ["desktop" "gui"];

    modules = [
      ./system.nix
    ];

    externalModules = [
      inputs.nix-index-database.darwinModules.nix-index
      inputs.determinate.darwinModules.default
    ];

    users.kenneth.modules = [m.homeManager.kenneth-alex];
  };
}
