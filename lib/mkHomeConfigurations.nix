{ inputs }:
{ hosts }:
let
  lib = inputs.nixpkgs.lib;
  hmLib = inputs.home-manager.lib;
  homeUtils = import ./home-utils.nix { inherit inputs; };

  mkHome = hostName: host: userName: user:
    let
      spec = homeUtils.mkHomeSpec {
        inherit host hostName userName user;
      };
    in
      hmLib.homeManagerConfiguration {
        inherit (spec) pkgs;
        modules = spec.modules ++ spec.extraImports;
        extraSpecialArgs = spec.specialArgs;
      };

  hostList = lib.mapAttrsToList (name: value: { inherit name value; }) hosts;
  hostHomePairs = lib.concatMap
    (hostEntry:
      let
        hostName = hostEntry.name;
        host = hostEntry.value;
        users = host.users or {};
      in
        lib.mapAttrsToList
          (userName: user: {
            name = "hosts/${hostName}/${userName}";
            value = mkHome hostName host userName user;
          })
          users
    )
    hostList;
in
  lib.listToAttrs hostHomePairs
