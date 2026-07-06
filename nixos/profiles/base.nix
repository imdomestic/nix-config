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

  # Per-host secrets live in secrets/hosts/<name>.yaml (encrypted to that
  # host's ssh-derived age key, see .sops.yaml); fall back to the shared file.
  sops = {
    defaultSopsFile = let
      perHost = ../../secrets/hosts + "/${config.my.host.name}.yaml";
    in
      lib.mkDefault (
        if builtins.pathExists perHost
        then perHost
        else ../../secrets/secrets.yaml
      );
    defaultSopsFormat = "yaml";
  };
}
