# kubectl / k9s 连 tank 上的运营集群。
#
# token 是 kube-system/hank 这个 ServiceAccount 的长期 token（k8s/apps/access），
# 存在 secrets/clients/kube-tank.yaml，只加密给 hank 自己的 key；kubeconfig 由
# sops 模板在激活时生成。撤销：删掉集群里的 hank-token，再把新 token 写回 sops。
{
  config,
  lib,
  ...
}: let
  home = config.home.homeDirectory;

  tankKubeconfig = {
    apiVersion = "v1";
    kind = "Config";
    clusters = [
      {
        name = "tank";
        cluster = {
          server = let
            p = config.my.fleet.placements.k3s-api;
          in "https://${p.tsName}:${toString p.port}";
          # k3s 第一次启动时生成的 CA，有效期到 2036。集群重装后要换这个文件。
          certificate-authority = "${./tank-ca.crt}";
        };
      }
    ];
    users = [
      {
        name = "tank-hank";
        user.token = config.sops.placeholder."kube/tank_token";
      }
    ];
    contexts = [
      {
        name = "tank";
        context = {
          cluster = "tank";
          user = "tank-hank";
          namespace = "mc";
        };
      }
    ];
    current-context = "tank";
  };
in {
  imports = [../sops];

  sops.secrets."kube/tank_token".sopsFile = ../../../../../secrets/clients/kube-tank.yaml;
  sops.templates."kube-tank.yaml".content = lib.generators.toYAML {} tankKubeconfig;

  # 第一个文件是 kubectl 写回 context 切换的地方，必须可写；sops 生成的文件只读，
  # 所以排在后面。k3s.yaml 是原来就有的入口，没有这个文件也不影响。
  home.sessionVariables.KUBECONFIG = "${home}/.config/k3s.yaml:${config.sops.templates."kube-tank.yaml".path}";

  # k9s 本身由 home/profiles/dev.nix 装，这里只写配置。
  programs.k9s = {
    enable = true;
    package = null;
    settings.k9s = {
      # 不去 GitHub 查新版本：版本由 nixpkgs 决定。
      skipLatestRevCheck = true;
      ui.enableMouse = true;
    };
  };
}
