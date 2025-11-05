{ lib, inputs, hostName, system, usernames ? [], hostUsers ? {}, ... }:
{
  imports = [
    ../../nixos/modules/nix.nix
    ../../nixos/modules/users.nix
    ../../nixos/modules/home-manager.nix
  ];

  networking.hostName = lib.mkDefault hostName;
  nixpkgs.hostPlatform = lib.mkDefault system;

  _module.args = {
    inherit inputs system hostName;
    usernames = if usernames != [] then usernames else builtins.attrNames hostUsers;
    hostUsers = hostUsers // lib.genAttrs usernames (_: {});
    hostname = hostName;
  };
}
