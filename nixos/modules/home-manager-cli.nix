# Home Manager is deliberately *not* a module of this system evaluation. Every
# user's home is its own closure (`homeConfigurations."hosts/<host>/<user>"`,
# built by lib/mkHomeConfigurations.nix) so that changing a home does not mean
# rebuilding and activating the whole machine.
#
# What the system still owes those users is the CLI. `programs.home-manager.enable`
# only puts `home-manager` *inside* a home generation, which is no help before
# the first activation — chicken and egg on a freshly installed machine.
#
# It comes from the flake input rather than `pkgs.home-manager`: the CLI and the
# modules that built the generation have to be the same release, and nixpkgs'
# copy drifts from `home-manager/release-26.05` independently.
{
  lib,
  inputs,
  system,
  config,
  ...
}:
lib.mkIf (config.my.host.users != {}) {
  environment.systemPackages = [
    inputs.home-manager.packages.${system}.home-manager
  ];
}
