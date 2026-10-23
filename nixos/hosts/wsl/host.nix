{
  config,
  inputs,
  ...
}: let
  m = config.flake.modules;
in {
  hosts.wsl = {
    system = "x86_64-linux";
    kind = "nixos";
    roles = ["cli"];

    profiles = [m.nixos.base];

    modules = [
      ./system.nix
    ];

    externalModules = [
      inputs.nixos-wsl.nixosModules.wsl
      inputs.nix-index-database.nixosModules.default
    ];

    users.hank = {};
  };
}
