# Where each fleet service runs (schema: ./schema/placements.nix). Clients read
# the resolved address from `config.my.fleet.placements.<service>` (`host`,
# `tsName`, `port`), so moving a service is this one line plus moving its
# server module to the new host.
{
  placements = {
    # CLIProxy:opencode / pi / max / gaoji 的模型网关。放在出境点 gizmo 上,
    # 见 docs/decisions.md#cliproxy-on-gizmo。
    cliproxy = {
      host = "gizmo";
      port = 8317;
    };
    rewind-balance = {
      host = "gizmo";
      port = 8318;
    };
    # gaoji 集群控制面(hosts/h610/cluster.nix),worker 和 tank 上的 bot 连它。
    gaoji-control = {
      host = "h610";
      port = 8091;
    };
    # Bonsai NInfer 网关,端口在 lib/bonsai-models.nix。
    bonsai-ninfer.host = "seraph";
    sillytavern = {
      host = "seraph";
      port = 8000;
    };
    lumiverse = {
      host = "seraph";
      port = 7861;
    };
    qwen-ninfer = {
      host = "taipan";
      port = 8000;
    };
    small-qwen = {
      host = "h610";
      port = 11435;
    };
    ollama = {
      host = "tank";
      port = 11434;
    };
    # k3s API(hosts/tank/k3s.nix),kubeconfig 用。
    k3s-api = {
      host = "tank";
      port = 6443;
    };
  };
}
