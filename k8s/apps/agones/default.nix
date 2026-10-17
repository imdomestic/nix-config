{lib, ...}: {
  applications.agones = {
    namespace = "agones-system";
    # 命名空间和 webhook 证书一起由 nixos/hosts/tank/k3s.nix 建。
    createNamespace = false;
    # CRD 里嵌着整份 PodTemplateSpec，client-side apply 会超出 annotation 的长度上限。
    syncPolicy.syncOptions.serverSideApply = true;

    helm.releases.agones = {
      chart = lib.helm.downloadHelmChart {
        repo = "https://agones.dev/chart/stable";
        chart = "agones";
        version = "1.61.0";
        chartHash = "sha256-T7tU2xghmz7MytJxYtxbZPl1yCwrIvuwekjlgQi/dAk=";
      };
      values = {
        agones = {
          # chart 默认在渲染时生成 webhook 证书，私钥会跟着进公开的渲染分支。
          # 这里只给公钥证书（server.crt），私钥由 NixOS 从 sops 写进 agones-cert。
          controller = {
            generateTLS = false;
            disableSecret = true;
            tlsCert = builtins.readFile ./server.crt;
          };
          extensions.generateTLS = false;
          # 分配走 K8s API 里的 GameServerAllocation，用不到对外的 allocator 服务。
          # install = false 不管它的 Secret，那几个 Secret 里是渲染时生成的私钥，要单独关掉。
          allocator = {
            install = false;
            disableSecretCreation = true;
          };
          ping.install = false;
          # 这是 Helm 的 pre-delete hook，Argo CD 下不会按预期运行。
          crds.cleanupOnDelete = false;
        };
        gameservers.namespaces = ["mc"];
      };
    };
  };
}
