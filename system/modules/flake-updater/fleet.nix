# What the updater compares between two revisions of the flake: each system's
# and home's drvPath, the versions that decide how a host has to be deployed,
# and the VM tests there are. `flakeRef` is a locked git+file reference.
# tryEval only catches throws and failed assertions; for anything else the
# updater evaluates the entries one at a time (flake-updater.sh: eval_each).
flakeRef: let
  flake = builtins.getFlake flakeRef;
  try = x: let
    r = builtins.tryEval (builtins.deepSeq x x);
  in
    if r.success
    then r.value
    else null;
  systemOf = c: try c.pkgs.stdenv.hostPlatform.system;
in {
  nixos =
    builtins.mapAttrs (_: c: {
      system = systemOf c;
      drv = try c.config.system.build.toplevel.drvPath;
      kernel = try c.config.boot.kernelPackages.kernel.version;
      nvidia = try (
        if c.config.hardware.nvidia.enabled or false
        then c.config.hardware.nvidia.package.version
        else null
      );
    })
    flake.nixosConfigurations;

  darwin =
    builtins.mapAttrs (_: c: {
      system = systemOf c;
      drv = try c.system.drvPath;
    })
    (flake.darwinConfigurations or {});

  # Each home is also exported as "<user>@<host>"; one name is enough.
  home = builtins.mapAttrs (_: c: {
    system = systemOf c;
    drv = try c.activationPackage.drvPath;
  }) (builtins.removeAttrs flake.homeConfigurations (builtins.filter (n: builtins.substring 0 6 n != "hosts/") (builtins.attrNames flake.homeConfigurations)));

  tests = builtins.attrNames (flake.fleetTests.x86_64-linux or {});
}
