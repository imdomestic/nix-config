# Where each fleet service runs (schema: ./schema/placements.nix). Clients read
# the resolved address from `config.my.fleet.placements.<service>` (`host`,
# `tsName`, `port`), so moving a service is this one line plus moving its
# server module to the new host.
{
  placements = {
    # CLIProxy:opencode / pi / max / gaoji 的模型网关。2026-10-14 从 h610 搬来。
    cliproxy = {
      host = "tank";
      port = 8317;
    };
    # gaoji 集群控制面(nixos/hosts/h610/cluster.nix),worker 和 tank 上的 bot 连它。
    gaoji-control = {
      host = "h610";
      port = 8091;
    };
    # Bonsai NInfer 网关,端口在 lib/bonsai-models.nix。
    bonsai-ninfer.host = "seraph";
    # k3s API(nixos/hosts/tank/k3s.nix),kubeconfig 用。
    k3s-api = {
      host = "tank";
      port = 6443;
    };
  };
}
