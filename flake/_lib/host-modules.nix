# The two modules every evaluation of a host starts with: the `my.host` /
# `my.fleet` schema, and this host's values for it out of the registry.
{
  config,
  lib,
}: let
  facts = h: {
    inherit (h) name system kind roles tsName ip sshUser lanRoutes gpuMonitoring clusterControl usernames;
  };
  fleet = {
    hosts = lib.mapAttrs (_: facts) config.hosts;
    inherit (config) inventory;
    placements = config.resolvedPlacements;
  };
in
  hostName: let
    h = config.hosts.${hostName};
  in [
    ../../modules/shared/host-options.nix
    {
      my.host = {
        inherit (h) name system roles tsName lanRoutes gpuMonitoring clusterControl homeOverlays users usernames;
      };
      my.fleet = fleet;
    }
  ]
