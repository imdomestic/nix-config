{
  lib,
  inputs,
  config,
  system,
  ...
}: {
  imports =
    [
      ../modules/nix.nix
      ../modules/users.nix
      ../modules/home-manager.nix
    ]
    ++ lib.optionals (lib.hasInfix "linux" system) [
      inputs.sops-nix.nixosModules.sops
    ]
    ++ lib.optionals (lib.hasInfix "darwin" system) [
      inputs.sops-nix.darwinModules.sops
    ];

  # Host metadata comes from config.my.host (see modules/shared/host-options.nix);
  # legacy module args are bridged centrally in lib/mkConfigurations.nix.
  nixpkgs.hostPlatform = lib.mkDefault system;
  networking.hostName = lib.mkDefault config.my.host.name;

  sops = {
    defaultSopsFile = ../../secrets/secrets.yaml;
    defaultSopsFormat = "yaml";
  };
}
