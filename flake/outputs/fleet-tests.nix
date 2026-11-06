# VM tests of the fleet's real host configurations (tests/). Not in `checks`
# for the same reason deployChecks is not: `nix flake check` would build them
# all. They need KVM: build them on tank (x86_64) or r6s (aarch64).
{
  config,
  inputs,
  lib,
  ...
}: let
  systemModules = import ../_lib/system-modules.nix {inherit config inputs lib;};
  testsOn = system:
    import ../../tests/lib.nix {
      inherit lib systemModules;
      pkgs = inputs.nixpkgs.legacyPackages.${system};
      nixos = config.flake.nixosConfigurations;
    };
  x86 = testsOn "x86_64-linux";
in {
  flake.fleetTests.x86_64-linux = {
    smoke-h310 = x86.smoke {hostName = "h310";};
  };
}
