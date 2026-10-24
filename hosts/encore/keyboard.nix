{
  config,
  lib,
  ...
}: let
  kernel = config.boot.kernelPackages.kernel;
in {
  # 修复受影响内核上的 ASUS N-Key 初始化握手。
  boot.extraModulePackages =
    lib.optionals
    (lib.versionAtLeast kernel.version "6.18.49" && lib.versionOlder kernel.version "6.18.54")
    [(config.boot.kernelPackages.callPackage ../../pkgs/hid-asus-handshake {})];
}
