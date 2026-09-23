{pkgs, ...}: {
  # hank 的 dev profile:共享工具链 + 打开 nixvim 的 dev 插件。
  # host 只需把 userModules.hank.dev 加进该用户的 home.modules 即可按需开启;
  # 没有 dev 的机器由 hank/default.nix 提供精简版 nixvim(保留 nix 支持)。
  imports = [
    ../../profiles/dev.nix
    ../../modules/nixvim/hank.nix
    ../../modules/opencode
  ];

  home.sessionVariables = {
    LAKE_ARTIFACT_CACHE = "1";
    LAKE_RESTORE_ARTIFACTS = "0";
    OPENCODE_ENABLE_EXA = "1";
  };

  my.nixvim.dev.enable = true;

  # nixvim 里 postgres_lsp 的可执行文件。只有 hank 在练 PG,不放共享的
  # profiles/dev.nix,免得 linwhite 也背上这 93 MB。
  home.packages = [pkgs.postgres-language-server];
}
