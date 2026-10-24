# 运营网络的集群：tank 上的单节点 k3s。
#
# 这里只管节点本身、Argo CD 的引导和密钥；集群里装什么写在 k8s/ 里，由 nixidy
# 渲染到 k8s-rendered 分支、Argo CD 应用。整体方案见 docs/minecraft-network-todo.md。
{
  config,
  lib,
  ...
}: let
  # Argo CD 跟踪的是渲染结果，不是 main：main 上只有 Nix 源码。
  renderedRepo = "https://github.com/imdomestic/nix-config.git";
  renderedBranch = "k8s-rendered";

  # k3s 会把 manifests 目录里的文件 apply 进集群。删掉文件不会删掉资源，
  # 所以这里只放引导用的东西，其余一律交给 Argo CD。
  # stringData 放单行明文；多行的值（PEM）以 base64 存在 sops 里、走 data。
  # sops 的占位符是原样替换的，多行内容替换进 YAML 字符串会被折成一行。
  secretManifest = namespace: name: {
    stringData ? {},
    data ? {},
  }:
    lib.generators.toYAML {} {
      apiVersion = "v1";
      kind = "List";
      items = [
        # 和密钥放在同一个文件里：Argo CD 还没把命名空间建出来时，这份也能 apply 成功。
        {
          apiVersion = "v1";
          kind = "Namespace";
          metadata.name = namespace;
        }
        {
          apiVersion = "v1";
          kind = "Secret";
          type = "Opaque";
          metadata = {inherit name namespace;};
          inherit stringData data;
        }
      ];
    };
in {
  services.k3s = {
    enable = true;
    role = "server";
    tokenFile = config.sops.secrets."k3s/token".path;
    # 不开 clusterInit，用默认的 SQLite：单节点用不上 etcd，而 etcd 会记住节点地址。
    # 加第二台 server 时再打开，k3s 会就地把 SQLite 转成 etcd。
    extraFlags = [
      # wg0 的地址是静态的；br-lan 走 DHCP，地址可能会变。
      "--node-ip=10.0.0.66"
      "--flannel-iface=wg0"
      # kubectl 从 tailnet 连进来。
      "--tls-san=tank.inner.imdomestic.com"
      "--tls-san=100.64.0.4"
      "--disable=traefik"
    ];
    # pause、coredns 这些系统镜像跟着 Nix 闭包装进来，开机不依赖能连上 Docker Hub。
    images = [config.services.k3s.package.airgap-images];

    autoDeployCharts.argo-cd = {
      repo = "https://argoproj.github.io/argo-helm";
      name = "argo-cd";
      version = "10.10.5";
      hash = "sha256-umRH7u1CvEHR8FJ3IQR7I2ME6XZpp7YobQK+ShZEuno=";
      targetNamespace = "argocd";
      createNamespace = true;
      values = {
        dex.enabled = false;
        notifications.enabled = false;
        # 界面只通过 kubectl port-forward 访问，不对外。
        configs.params."server.insecure" = true;
      };
    };

    manifests = {
      # 根 Application。内容和 `nixidy bootstrap .#tank` 的输出相同；之后的所有
      # Application（包括它自己）都来自渲染分支里的 tank/apps。
      argocd-root.content = {
        apiVersion = "argoproj.io/v1alpha1";
        kind = "Application";
        metadata = {
          name = "apps";
          namespace = "argocd";
        };
        spec = {
          project = "default";
          source = {
            repoURL = renderedRepo;
            targetRevision = renderedBranch;
            path = "./tank/apps";
          };
          destination = {
            server = "https://kubernetes.default.svc";
            namespace = "argocd";
          };
          syncPolicy.automated = {
            prune = true;
            selfHeal = true;
          };
        };
      };

      # 渲染分支是公开的，密钥只能从这里进集群。
      mc-secrets.source = config.sops.templates."k3s-mc-secrets.yaml".path;
      agones-cert.source = config.sops.templates."k3s-agones-cert.yaml".path;
    };
  };

  sops.secrets = {
    "k3s/token" = {};
    "k3s/agones_tls_key_b64" = {};
    "mc/forwarding_secret" = {};
  };

  sops.templates = {
    "k3s-mc-secrets.yaml".content = secretManifest "mc" "velocity-forwarding" {
      stringData.secret = config.sops.placeholder."mc/forwarding_secret";
    };
    # Agones 的 webhook 证书。chart 自己生成的话，私钥会跟着渲染结果进公开分支，
    # 所以关掉生成，公钥证书放在 k8s/apps/agones/server.crt，私钥从 sops 来。
    "k3s-agones-cert.yaml".content = secretManifest "agones-system" "agones-cert" {
      stringData."server.crt" = builtins.readFile ../../k8s/apps/agones/server.crt;
      data."server.key" = config.sops.placeholder."k3s/agones_tls_key_b64";
    };
  };
}
