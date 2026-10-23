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
    # wireguard 那张网上的地址,可能没有(gizmo 就没有)。这里带出来只是为了
    # 提供其他网络路径的主机元数据,监控本身不用它。
    wgIp = h.ip;
  }) (lib.filterAttrs (_: h: h.tsName != null) config.hosts);
}
