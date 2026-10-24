{inputs, ...}: {
  hosts.praxic = {
    system = "aarch64-darwin";
    kind = "darwin";
    roles = ["desktop" "gui"];

    modules = [
      ./system.nix
    ];

    externalModules = [
      inputs.nix-index-database.darwinModules.nix-index
      inputs.determinate.darwinModules.default
    ];

    users.hank = {
      # 写了 uid 就等于把这个账户交给 nix-darwin 管(见 system/modules/users.nix),
      # 登录 shell 才会真的落到 pkgs.zsh 上,不用手动 chsh。迁移后激活前必须核对
      # hank 的实际 uid，见 docs/mac-migration.md#nix-restore。
      #
      # description 显式写成现在的 RealName:模块里它默认取用户名,而 nix-darwin 会把
      # description 写进 RealName,不写的话"Hank Hogan"会被改成"hank"。
      nixos = {
        uid = 501;
        description = "Hank Hogan";
      };
      ageKey = "age1uumwl2zvv6sk2yysjtd29yfffjj8xfus6z95eu0ftxt40mnyh9aq3g5f2c";
    };
  };
}
