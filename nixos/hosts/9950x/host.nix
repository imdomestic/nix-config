{
  config,
  inputs,
  ...
}: let
  m = config.flake.modules;
in {
  hosts."9950x" = {
    system = "x86_64-linux";
    kind = "nixos";
    roles = ["cli" "gui"];

    profiles = [m.nixos.base];

    modules = [
      ./system.nix
      m.nixos.sudo-pwfeedback
    ];

    externalModules = [
      inputs.nixos-wsl.nixosModules.wsl
      inputs.nix-index-database.nixosModules.default
    ];

    users.linwhite = {};
  };
}
