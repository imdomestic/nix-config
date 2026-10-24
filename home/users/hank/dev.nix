{pkgs, ...}: {
  # hank 的 dev profile:共享工具链 + 打开 nixvim 的 dev 插件。
  # 账户到 dev 档时由 flake/builders/homes.nix 加载(见 ./user.nix);
  # 没有 dev 的机器由 hank/default.nix 提供精简版 nixvim(保留 nix 支持)。
  imports = [
    ./modules/dev-tools.nix
    ./modules/nixvim/default.nix
    ./modules/nixvim/java.nix
    ./modules/nixvim/dap.nix
    ./modules/claude-code
    # kubectl/k9s 在 modules/dev-tools.nix 里,kubeconfig 跟着走,不往路由器上解密集群 token。
    ./modules/kube
    ./modules/lazygit
    ./modules/codex
    ./modules/opencode
    ./modules/pi
  ];

  home.sessionVariables = {
    LAKE_ARTIFACT_CACHE = "1";
    LAKE_RESTORE_ARTIFACTS = "0";
    OPENCODE_ENABLE_EXA = "1";
  };

  my.nixvim.dev.enable = true;

  # nixvim 里 postgres_lsp 的可执行文件。只有 hank 在练 PG,不放共享的
  # modules/dev-tools.nix(那份 linwhite 也有一份),免得她也背上这 93 MB。
  home.packages = [pkgs.postgres-language-server pkgs.jdt-language-server];
}
