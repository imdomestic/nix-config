# 运营集群 tank 的 nixidy 环境。
#
# 渲染结果由 .github/workflows/k8s.yml 推到 k8s-rendered 分支的 tank/ 下；
# Argo CD 的根 Application、密钥和命名空间在 nixos/hosts/tank/k3s.nix 里。
{
  imports = [
    ./apps/access
    ./apps/agones
    ./apps/mc
  ];

  nixidy = {
    target = {
      repository = "https://github.com/imdomestic/nix-config.git";
      branch = "k8s-rendered";
      rootPath = "./tank";
    };

    defaults.syncPolicy.autoSync = {
      enable = true;
      prune = true;
      selfHeal = true;
    };
  };
}
