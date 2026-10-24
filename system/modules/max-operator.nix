{
  lib,
  pkgs,
  system,
  ...
}: let
  darwin = lib.hasSuffix "darwin" system;
in
  lib.mkMerge [
    {
      users.users.max = {
        description = "Max fleet operator";
        shell = pkgs.bashInteractive;
        home =
          if darwin
          then "/Users/max"
          else "/home/max";
      };
    }
    (lib.optionalAttrs (!darwin) {
      users.users.max = {
        isNormalUser = true;
        group = "max";
        createHome = true;
        hashedPassword = "!";
        extraGroups = [];
      };
      users.groups.max = {};
      security.sudo.extraRules = [
        {
          users = ["max"];
          commands = [
            {
              command = "ALL";
              options = ["NOPASSWD"];
            }
          ];
        }
      ];
    })
    (lib.optionalAttrs darwin {
      users.knownUsers = ["max"];
      users.users.max = {
        uid = 550;
        createHome = true;
      };
      security.sudo.extraConfig = "max ALL=(ALL) NOPASSWD: ALL\n";
    })
  ]
