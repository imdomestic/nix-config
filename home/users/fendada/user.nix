{config, ...}: let
  hm = config.flake.modules.homeManager;
in {
  flake.modules.homeManager.fendada = ./default.nix;

  users.fendada = {
    module = hm.fendada;
    ageKeys.personal = "age1ctfjwk8fkfuxq9rrsuenmqtx8l3jx5rt4hujvh525pgruxs69fls4qtj7z"; # 1823215739@qq.com
  };

  # macbook-pro-3 上的账户名。和 fendada 用同一份 home,只到 minimal 档。
  users.a123456 = {
    tier = "minimal";
    module = hm.fendada;
  };
}
