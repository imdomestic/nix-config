{
  lib,
  config,
  system,
  ...
}: {
  imports = [
    ../../nixos/modules/nix.nix
    ../../nixos/modules/users.nix
    ../../nixos/modules/home-manager.nix
  ];

  # Host metadata comes from config.my.host (see modules/shared/host-options.nix);
  # legacy module args are bridged centrally in lib/mkConfigurations.nix.
  networking.hostName = lib.mkDefault config.my.host.name;
  nixpkgs.hostPlatform = lib.mkDefault system;
}
