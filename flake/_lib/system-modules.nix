# What a host's system evaluation is made of: its module list and specialArgs.
# flake/builders/systems.nix builds every configuration from this; the fleet
# tests (flake/outputs/fleet-tests.nix) boot the same list in a VM, minus the
# files that describe real hardware.
{
  config,
  inputs,
  lib,
}: let
  hostModules = import ./host-modules.nix {inherit config lib;};
  roles = import ./roles.nix;

  # Profiles come in this order whatever order a host lists its roles in.
  # Module order is definition order for list options (systemPackages…), so it
  # is fixed here rather than taken from attrNames, which sorts.
  profileOrder = ["server" "desktop" "router" "vm-host"];
  base = {
    nixos = ../../system/profiles/base.nix;
    darwin = ../../system/profiles/darwin.nix;
  };
  profilesOf = host:
    lib.throwIfNot (lib.all (r: roles.${r} ? profiles -> lib.elem r profileOrder) (lib.attrNames roles))
    "flake/_lib/system-modules.nix: every role with profiles must be in profileOrder"
    ([base.${host.kind}]
      ++ lib.concatMap (r: roles.${r}.profiles.${host.kind} or [])
      (lib.filter (r: lib.elem r host.roles) profileOrder));

  # The host's own files that load by name, ahead of whatever host.nix lists.
  byName = host: n: let
    f = host.dir + "/${n}.nix";
  in
    lib.optional (builtins.pathExists f) f;
in
  {
    hostName,
    # false: leave out hardware-configuration.nix and hardwareModules, for a VM.
    withHardware ? true,
  }: let
    host = config.hosts.${hostName};
  in {
    modules =
      hostModules hostName
      ++ lib.unique (profilesOf host
        ++ byName host "system"
        ++ lib.optionals withHardware (byName host "hardware-configuration")
        ++ host.modules
        ++ lib.optionals withHardware host.hardwareModules
        ++ host.externalModules);
    # `system` and `inputs` stay specialArgs because base profiles use them
    # in `imports`, which cannot depend on config. Everything else lives in
    # `config.my.host`.
    specialArgs = {
      inherit inputs;
      inherit (host) system;
      "pkgs-unstable" = import inputs.nixpkgs-unstable {
        inherit (host) system;
        overlays = [inputs.nur.overlays.default];
        config = import ./nixpkgs-config.nix;
      };
    };
  }
