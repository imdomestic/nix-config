# lib/mkDeployNodes.nix
{inputs}: {
  hosts,
  nixosConfigurations,
}: let
  inherit (inputs.nixpkgs) lib;
  deploy-rs = inputs.deploy-rs;
in
  lib.mapAttrs (
    name: hostConfig: let
      isDeployable = (hostConfig ? ip) && (builtins.hasAttr name nixosConfigurations);
    in
      if isDeployable
      then {
        hostname = hostConfig.ip;

        fastConnection = false;
        autoRollback = true;
        magicRollback = true;
        activationTimeout = 120;

        profiles.system = {
          user = "root";
          sshUser = hostConfig.sshUser or "root";
          path = deploy-rs.lib.${hostConfig.system}.activate.nixos nixosConfigurations.${name};
        };
      }
      else {}
  )
  (lib.filterAttrs (n: v: (v ? ip) && (v.kind or "nixos" == "nixos")) hosts)
