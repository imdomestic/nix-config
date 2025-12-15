{
  lib,
  inputs,
  host ? {},
  hostName ? "",
  ...
}: let
  homeUtils = import ../../lib/home-utils.nix {inherit inputs;};
  users = host.users or {};
  actualHostName =
    if hostName != ""
    then hostName
    else (host.name or "");
  mkUser = userName: user: let
    spec = homeUtils.mkHomeSpec {
      inherit host userName user;
      hostName = actualHostName;
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
  hmUsers = lib.mapAttrs mkUser users;
  hasUsers = hmUsers != {};
in
  lib.mkIf hasUsers {
    home-manager.useGlobalPkgs = false;
    home-manager.useUserPackages = true;
    home-manager.extraSpecialArgs = {
      inherit inputs;
      hostName = actualHostName;
      hostname = actualHostName;
    };
    home-manager.users = hmUsers;
  }
