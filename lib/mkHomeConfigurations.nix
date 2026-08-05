{inputs}: {hosts}: let
  lib = inputs.nixpkgs.lib;
  hmLib = inputs.home-manager.lib;
  homeUtils = import ./home-utils.nix {inherit inputs;};

  mkHome = hostName: host: userName: user: basePkgs: let
    spec = homeUtils.mkHomeSpec {
      inherit host hostName userName user basePkgs;
    };
  in
    hmLib.homeManagerConfiguration {
      inherit (spec) pkgs;
      modules = spec.modules ++ spec.extraImports;
      extraSpecialArgs = spec.specialArgs;
    };

  hostList = lib.mapAttrsToList (name: value: {inherit name value;}) hosts;
  hostHomePairs =
    lib.concatMap
    (
      hostEntry: let
        hostName = hostEntry.name;
        host = hostEntry.value;
        users = host.users or {};
        basePkgs = homeUtils.mkBasePkgs {inherit host;};
      in
        lib.concatLists (
          lib.mapAttrsToList
          (
            userName: user: let
              cfg = mkHome hostName host userName user basePkgs;
            in [
              # Canonical name — what `just hm` and the deploy nodes resolve.
              {
                name = "hosts/${hostName}/${userName}";
                value = cfg;
              }
              # What the home-manager CLI looks up by itself when given a bare
              # flake reference (it tries `$USER@$(hostname)`, then `$USER`), so
              # on the machine itself no attribute path has to be spelled out.
              {
                name = "${userName}@${hostName}";
                value = cfg;
              }
            ]
          )
          users
        )
    )
    hostList;
in
  lib.listToAttrs hostHomePairs
