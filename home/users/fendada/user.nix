{
  users.fendada.ageKeys.personal = "age1ctfjwk8fkfuxq9rrsuenmqtx8l3jx5rt4hujvh525pgruxs69fls4qtj7z"; # 1823215739@qq.com

  # macbook-pro-3 上的账户名。和 fendada 用同一个目录(macbook-pro-3.nix 也在这里),
  # 只到 minimal 档。
  users.a123456 = {
    tier = "minimal";
    dir = ./.;
  };
}
