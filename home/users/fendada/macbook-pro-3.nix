# a123456(fendada 的 home)在 macbook-pro-3 上的东西。
{lib, ...}: {
  # The macOS account name and its actual home directory differ on this
  # machine, so override Home Manager's conventional /Users/<name> path.
  home.homeDirectory = lib.mkForce "/Users/a123456_1_2";
}
