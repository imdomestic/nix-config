{
  config,
  lib,
  ...
}: let
  kernel = config.boot.kernelPackages.kernel;
in {
  # ASUS N-Key 初始化修复；适用内核及验证见 docs/encore-keyboard.md。
  boot.extraModulePackages =
    lib.optionals
    (lib.versionAtLeast kernel.version "6.18.49" && lib.versionOlder kernel.version "6.18.54")
    [(config.boot.kernelPackages.callPackage ../../../pkgs/hid-asus-handshake {})];
}
