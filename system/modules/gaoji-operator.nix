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
      users.users.gaoji = {
        description = "gaoji fleet operator (Tailscale SSH from the gaoji-ops node)";
        shell = pkgs.bashInteractive;
        home =
          if darwin
          then "/Users/gaoji"
          else "/home/gaoji";
      };
    }
    (lib.optionalAttrs (!darwin) {
      users.users.gaoji = {
        isNormalUser = true;
        group = "gaoji";
        createHome = true;
        hashedPassword = "!";
        extraGroups = [];
      };
      users.groups.gaoji = {};
      security.sudo.extraRules = [
        {
          users = ["gaoji"];
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
      users.knownUsers = ["gaoji"];
      users.users.gaoji = {
        uid = 551;
        createHome = true;
      };
      security.sudo.extraConfig = "gaoji ALL=(ALL) NOPASSWD: ALL\n";
    })
  ]
