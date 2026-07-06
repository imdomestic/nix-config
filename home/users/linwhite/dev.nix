{...}: {
  # linwhite 的 dev profile:共享工具链 + 打开 nixvim 的 dev 插件。
  # host 只需把 userModules.linwhite.dev 加进该用户的 home.modules 即可按需开启;
  # 没有 dev 的机器由 linwhite/default.nix 提供精简版 nixvim(保留 nix 支持)。
  imports = [
    ../../profiles/dev.nix
    ../../modules/nixvim/linwhite.nix
  ];

  my.nixvim.dev.enable = true;
}
