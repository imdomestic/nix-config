{
  config,
  inputs,
  ...
}: {
  # The registry itself, for `nix eval .#hosts.<name>.tsName` and CI's inventory table.
  flake.hosts = config.hosts;

  # 运营集群（tank 上的 k3s）的 k8s 配置。.github/workflows/k8s.yml 渲染后推到
  # k8s-rendered 分支，Argo CD 从那里拉。本地看渲染结果：
  #   nix run github:arnarg/nixidy -- build .#tank
  flake.nixidyEnvs = inputs.nixpkgs.lib.genAttrs ["x86_64-linux" "aarch64-darwin"] (system:
    inputs.nixidy.lib.mkEnvs {
      pkgs = inputs.nixpkgs.legacyPackages.${system};
      envs.tank.modules = [../../k8s/tank.nix];
    });

  # 运营网络镜像的 tag（minecraft/ 的内容哈希），CI 推镜像时用，见 minecraft/image-tag.nix。
  flake.mcImageTag = import ../../minecraft/image-tag.nix;
}
