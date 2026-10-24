# hank 在 encore 上的东西。
{lib, ...}: {
  # 休眠的两个键由这台 system.nix 的 dconf 数据库锁定,home 不能再写。
  dconf.settings."org/gnome/settings-daemon/plugins/power" = lib.mkForce {};
}
