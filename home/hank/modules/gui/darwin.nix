{
  pkgs,
  lib,
  ...
}: {
  imports = [./common.nix];

  # macmon 只支持 Apple Silicon；hackintosh 是 x86_64-darwin。
  home.packages = lib.optional pkgs.stdenv.hostPlatform.isAarch64 pkgs.macmon;
}
