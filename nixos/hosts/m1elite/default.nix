{inputs}: let
  darwinProfiles = import ../../../darwin/profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "aarch64-darwin";
  kind = "darwin";
  roles = ["desktop" "gui"];

  profiles = with darwinProfiles; [
    base
  ];

  modules = [
    ./system.nix
  ];

  externalModules = [
    inputs.nix-index-database.darwinModules.nix-index
    inputs.determinate.darwinModules.default
  ];

  users = {
    hank = {
      # 写了 uid 就等于把这个账户交给 nix-darwin 管(见 nixos/modules/users.nix),
      # 登录 shell 才会真的落到 pkgs.zsh 上,不用手动 chsh。501 是这台机器上 hank
      # 的实际 uid —— 必须一致,否则 nix-darwin 会跳过整个账户。
      #
      # description 显式写成现在的 RealName:模块里它默认取用户名,而 nix-darwin 会把
      # description 写进 RealName,不写的话"Hank Hogan"会被改成"hank"。
      nixos = {
        uid = 501;
        description = "Hank Hogan";
      };
      home = {
        profiles = with homeProfiles; [
          core
          base
          gui.darwin
        ];
        modules = [
          userModules.hank.module
          userModules.hank.dev
        ];
      };
    };
  };
}
