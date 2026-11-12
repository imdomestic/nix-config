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

  # 点按 Tab 输出 Tab，组合键作为 Alt（与 macOS 上 Option 键位一致）。
  services.keyd.keyboards.default.settings.main.tab = "overload(alt, tab)";
}
