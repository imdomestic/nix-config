{
  lib,
  inputs,
  hostName,
  system,
  usernames ? [],
  hostUsers ? {},
  ...
}: {
  imports = [
    ../modules/nix.nix
    ../modules/users.nix
    ../modules/home-manager.nix
  ];

  # Provide host metadata to downstream modules
  nixpkgs.hostPlatform = lib.mkDefault system;

  # Make hostName available as an option for other modules that expect it.
  networking.hostName = lib.mkDefault hostName;

  # Allow modules that still rely on the usernames list to work
  _module.args = {
    inherit inputs system hostName;
    usernames =
      if usernames != []
      then usernames
      else builtins.attrNames hostUsers;
    hostUsers = hostUsers // lib.genAttrs usernames (_: {});
    hostname = hostName;
  };
}
