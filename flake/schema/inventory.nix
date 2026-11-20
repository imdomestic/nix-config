# The managed hosts — those that opted in with a tsName — in the record shape
# monitoring, telemetry, deployment and cluster control consume.
{
  config,
  lib,
  ...
}: {
  options.inventory = lib.mkOption {
    type = lib.types.listOf lib.types.raw;
    readOnly = true;
    description = "Managed hosts, sorted by name.";
  };

  config.inventory = lib.mapAttrsToList (name: h: {
    inherit name;
    inherit (h) tsName system kind roles gpuMonitoring clusterControl;
  }) (lib.filterAttrs (_: h: h.tsName != null) config.hosts);
}
