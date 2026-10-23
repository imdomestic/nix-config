{
  config,
  inputs,
  ...
}: let
  m = config.flake.modules;
in {
  hosts.aarch64-wsl = {
    system = "aarch64-linux";
    kind = "nixos";
    roles = ["server"];

    profiles = with m.nixos; [
      base
      server
      # desktop
    ];

    modules = [
      ./system.nix
    ];

    externalModules = [
      inputs.nixos-wsl.nixosModules.default
      inputs.nix-index-database.nixosModules.default
      inputs.sops-nix.nixosModules.sops
    ];

    users.hank = {};
  };
}
