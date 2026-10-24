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
    ./host-options.nix
    {
      my.host = {
        inherit (h) name system roles inChina tsName lanRoutes gpuMonitoring clusterControl homeOverlays usernames;
        # The account table's ssh keys travel with each account
        # (system/modules/users.nix turns them into authorized keys).
        users = lib.mapAttrs (a: acct: let
          keys = config.users.${a}.sshKeys or [];
        in
          acct // lib.optionalAttrs (keys != []) {sshKeys = keys;})
        h.users;
      };
      my.fleet = fleet;
    }
  ]
