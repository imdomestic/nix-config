# kubectl / k9s 连 tank 上的运营集群。
#
# kubeconfig 里只有 API 地址和 CA 证书，没有凭据：每次要 token 时，exec 插件用现有
# 的 ssh root@tank 现签一个 12 小时的 ServiceAccount token（账号在
# k8s/apps/access）。哪台机器 ssh 不上 root@tank，这个 context 就用不了。
{
  config,
  lib,
  pkgs,
  ...
}: let
  home = config.home.homeDirectory;

  tankToken = pkgs.writeShellScript "kube-tank-token" ''
    set -euo pipefail
    # 用 PATH 里的 ssh，才吃得到 ~/.ssh/config 和系统的 agent。
    ssh -o BatchMode=yes root@tank.inner.imdomestic.com \
      k3s kubectl create token hank --namespace kube-system --duration 12h --output json |
      ${lib.getExe pkgs.jq} '{
        apiVersion: "client.authentication.k8s.io/v1",
        kind: "ExecCredential",
        status: {token: .status.token, expirationTimestamp: .status.expirationTimestamp}
      }'
  '';

  tankKubeconfig = {
    apiVersion = "v1";
    kind = "Config";
    clusters = [
      {
        name = "tank";
        cluster = {
          server = "https://tank.inner.imdomestic.com:6443";
          # k3s 第一次启动时生成的 CA，有效期到 2036。集群重装后要换这个文件。
          certificate-authority = "${./tank-ca.crt}";
        };
      }
    ];
    users = [
      {
        name = "tank-hank";
        user.exec = {
          apiVersion = "client.authentication.k8s.io/v1";
          command = "${tankToken}";
          interactiveMode = "Never";
        };
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
  xdg.configFile."kube/tank.yaml".text = lib.generators.toYAML {} tankKubeconfig;

  # 第一个文件是 kubectl 写回 context 切换的地方，必须可写，所以由 home-manager 生成
  # 的 tank.yaml 只能排在后面。k3s.yaml 是原来就有的入口，没有这个文件也不影响。
  home.sessionVariables.KUBECONFIG = "${home}/.config/k3s.yaml:${home}/.config/kube/tank.yaml";

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
