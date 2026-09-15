# Managed hosts opt in with a fully qualified MagicDNS name.
# The same registry feeds deployment, telemetry and service discovery.
{inputs}: {hosts}: let
  lib = inputs.nixpkgs.lib;

  managed = lib.filterAttrs (_: h: (h.tsName or null) != null) hosts;
in
  lib.mapAttrsToList (name: h: {
    inherit name;
    tsName = h.tsName;
    system = h.system;
    kind = h.kind or "nixos";
    roles = h.roles or [];
    gpuMonitoring =
      {
        enable = false;
        uuids = [];
      }
      // (h.gpuMonitoring or {});
    clusterControl =
      {
        enable = false;
        readableUnits = [];
        manageableUnits = [];
      }
      // (h.clusterControl or {});
    # wireguard 那张网上的地址,可能没有(r5sjp 就没有)。这里带出来只是为了
    # 提供其他网络路径的主机元数据,监控本身不用它。
    wgIp = h.ip or null;
  })
  managed
