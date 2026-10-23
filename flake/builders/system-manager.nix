# systemConfigs for hosts with `systemManager.enable` (Linux only). Exposed as
# systemConfigs.<host>, .hosts.<host>, .<system>.<host> and .<system>.hosts.<host>.
{
  config,
  inputs,
  lib,
  ...
}: let
  hostModules = import ../_lib/host-modules.nix {inherit config lib;};

  mkSystemConfig = hostName: host: let
    sysman = host.systemManager;
  in
    lib.throwIfNot (lib.hasInfix "linux" host.system)
    "system-manager configs are only supported for Linux hosts (${hostName})"
    inputs.system-manager.lib.makeSystemConfig {
      modules =
        hostModules hostName
        ++ [
          {nixpkgs.hostPlatform = lib.mkDefault host.system;}
        ]
        ++ sysman.modules;
      inherit (sysman) overlays;
      extraSpecialArgs = {
        inherit inputs;
        inherit (host) system;
        "pkgs-unstable" = import inputs.nixpkgs-unstable {
          inherit (host) system;
          overlays = sysman.overlays ++ [inputs.nur.overlays.default];
          config = import ../_lib/nixpkgs-config.nix;
        };
      };
    };

  perHost = hostName: host: let
    cfg = mkSystemConfig hostName host;
  in
    lib.foldl' lib.recursiveUpdate {} [
      {${hostName} = cfg;}
      {hosts.${hostName} = cfg;}
      {${host.system}.${hostName} = cfg;}
      {${host.system}.hosts.${hostName} = cfg;}
    ];
in {
  flake.systemConfigs =
    lib.foldl' lib.recursiveUpdate {}
    (lib.mapAttrsToList perHost (lib.filterAttrs (_: h: h.systemManager.enable) config.hosts));
}
