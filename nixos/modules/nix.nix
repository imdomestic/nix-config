{inputs, ...}: let
  registryPins = import ../../lib/nixpkgs-registry.nix {inherit inputs;};
in {
  # The options below come from nixpkgs' config/nix-flakes.nix,
  # config/nix-channel.nix and config/nix-remote-build.nix, none of which
  # system-manager imports — hence the split. system-manager hosts take
  # nix-settings.nix plus nix-registry-etc.nix instead of this module.
  imports = [./nix-settings.nix];

  nixpkgs = {
    overlays = [
      inputs.nur.overlays.default
      inputs.nix-minecraft.overlay
      # inputs.headplane.overlays.default
      (final: prev: {
        zjstatus = inputs.zjstatus.packages.${prev.system}.default;
      })
    ];
    config = {
      allowUnfree = true;
    };
  };

  # nix.optimise.automatic = true;

  # nix.gc = {
  #   automatic = true;
  #   options = "--delete-older-than 1w";
  # };

  nix = {
    # See lib/nixpkgs-registry.nix for why these are github refs and not the
    # `flake = inputs.nixpkgs` shorthand.
    registry = registryPins.registry;
    nixPath = [
      "nixpkgs=${inputs.nixpkgs}"
      "nixpkgs-unstable=${inputs.nixpkgs-unstable}"
    ];
    channel.enable = false;
    distributedBuilds = true;
  };

  # nix.buildMachines = [
  #   {
  #     hostName = "tank";
  #     system = "x86_64-linux";
  #     maxJobs = 20;
  #     speedFactor = 2;
  #     supportedFeatures = ["nixos-test" "benchmark" "big-parallel" "kvm"];
  #   }
  # ];
}
