# **CI 矩阵的唯一真源。** ci.yml 原来手抄一份 17 条的 include 列表,而它已经
# 漂了:h310(2026-08-14 加的)、marble、alex 三台从来没进过矩阵 —— 其中 h310
# 正是把 `nix flake check` 撑爆的那台(docs/incidents.md#deploy-schema-timeout),
# 加机器的人改了 hosts 却没人记得改 workflow。
#
# 所以这里给的是**规则**而不是名单:
#   kind == "home"   跳过 —— 那几台只有 home 配置,没有 system 可以 build
#   x86_64-darwin    跳过 —— 没有可用 runner(macos-13 正在退役,而且 26.05 是
#                    nixpkgs 最后一个支持 x86_64-darwin 的版本)。hackintosh
#                    走的就是这条,而不是被人忘在名单外。
#
# 新加一台机器只要它有 system 配置,下一次 CI 就自动带上它。
{
  config,
  lib,
  ...
}: let
  # system -> GitHub runner。aarch64-linux 用原生 arm64 runner(公开仓库免费),
  # 不要退回 ubuntu-latest + QEMU —— 理由见 cachix.yml 里那段。
  runners = {
    "x86_64-linux" = "ubuntu-latest";
    "aarch64-linux" = "ubuntu-24.04-arm";
    "aarch64-darwin" = "macos-latest";
  };
in {
  flake.ciMatrix = lib.pipe config.hosts [
    (lib.filterAttrs (_: h: h.kind != "home" && runners ? ${h.system}))
    (lib.mapAttrsToList (host: h: {
      inherit host;
      inherit (h) kind system;
      os = runners.${h.system};
      # 表格里显示用。darwin 保留全称,免得和 aarch64-linux 混淆。
      arch =
        if lib.hasSuffix "-darwin" h.system
        then h.system
        else lib.head (lib.splitString "-" h.system);
    }))
  ];
}
