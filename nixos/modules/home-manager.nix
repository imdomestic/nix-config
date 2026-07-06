{
  lib,
  inputs,
  config,
  ...
}: let
  homeUtils = import ../../lib/home-utils.nix {inherit inputs;};
  hostMeta = config.my.host;
  mkUser = userName: user: let
    spec = homeUtils.mkHomeSpec {
      host = {
        inherit (hostMeta) system roles users homeOverlays;
      };
      hostName = hostMeta.name;
      inherit userName user;
    };
    argsModule = {
      _module.args =
        spec.specialArgs
        // {
          pkgs = lib.mkForce spec.pkgs;
        };
    };
  in {
    imports = [argsModule] ++ spec.modules ++ spec.extraImports;
  };
  hmUsers = lib.mapAttrs mkUser hostMeta.users;
  hasUsers = hmUsers != {};
in
  lib.mkIf hasUsers {
    home-manager.useGlobalPkgs = false;
    home-manager.useUserPackages = true;
    home-manager.backupFileExtension = "backup";
    home-manager.extraSpecialArgs = {
      inherit inputs;
      hostName = hostMeta.name;
      hostname = hostMeta.name;
    };
    home-manager.users = hmUsers;
  }
