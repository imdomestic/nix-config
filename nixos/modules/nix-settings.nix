# The portable half of the Nix configuration: what ends up in nix.conf.
#
# Kept separate from nix.nix because system-manager hosts import only nixpkgs'
# config/nix.nix, so `nix.settings` resolves there while `nix.registry` /
# `nixPath` / `channel` / `distributedBuilds` do not. Nothing here may touch
# `nixpkgs.*` either — system-manager instantiates pkgs from the overlays passed
# to makeSystemConfig, and defining `nixpkgs.overlays` on top of that sends the
# module system into infinite recursion via users-groups.nix's `pkgs.shadow`.
{
  config,
  lib,
  options,
  ...
}: let
  substituters = [
    # 数字越小越优先:SJTU 镜像加速 -> 官方源兜底 -> 其余专用 cache
    "https://mirror.sjtu.edu.cn/nix-channels/store?priority=10"
    "https://cache.nixos.org?priority=20"
    # cache.garnix.io 拿掉了。唯一走 garnix CI 的 input 是 nix-index-database,
    # 而它的全部产物就是两个 fetchurl(FOD,内容寻址,直接从 GitHub release 下)
    # 加几个 symlinkJoin wrapper(本地瞬间就建完)—— 一个都不靠它。留着的净效果
    # 只是每次求值多打一轮 narinfo,而它一 502 就能把整个构建拖停。
    # 自建 cache。里面只有 cache.nixos.org 一定没有的那几条:rpi4 被
    # nixos-hardware 改过的内核、mihomo-smart、自制字体。
    # 内容清单见 flake.nix 的 packages 输出,推送在 .github/workflows/cachix.yml。
    # 排在官方源之后:能命中的就那几条路径,让 sjtu/官方先答更划算。
    "https://imdomestic.cachix.org?priority=30"
    "https://cache.iog.io?priority=40"
    "https://cache.nixos-cuda.org?priority=50"
    # llm-agents(cli-proxy-api)。这个 flake 自己的 nixConfig 里声明了这个
    # substituter,但 flake input 的 nixConfig 不会被应用,只有把它当顶层 flake
    # 跑才会提示 --accept-flake-config,所以必须在这里显式写一遍。
    # 少了它,llm-agents 就得在本地从源码编 —— 那正是不 follows 我们 nixpkgs
    # 的全部意义所在。
    "https://cache.numtide.com?priority=60"
  ];

  publicKeys = [
    "imdomestic.cachix.org-1:FySNifimqAiSSymMUb2ovlNZ5+xrCcO/bebqKrJd2pM="
    "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
    "cache.nixos-cuda.org:74DUi4Ye579gUqzH4ziL9IyiJBlDpMRn9MBN8oNan9M="
    "niks3.numtide.com-1:DTx8wZduET09hRmMtKdQDxNNthLQETkc/yaX7M4qK0g="
  ];

  # Hosts that hand Nix to Determinate set `nix.enable = false`, which drops
  # nix-darwin's nix module and every `nix.settings` definition with it —
  # silently. Route the same values to Determinate's sink instead so this file
  # stays the only place these are written down.
  viaDeterminate = options ? determinateNix && config.determinateNix.enable;
in {
  # The registry pins route the same three ways, so every host that gets these
  # settings gets those too.
  imports = [./nix-registry.nix];

  config = lib.mkMerge (
    [
      (lib.mkIf (!viaDeterminate) {
        nix.settings = {
          inherit substituters;
          trusted-public-keys = publicKeys;
          trusted-users = config.my.host.usernames;
          experimental-features = ["nix-command" "flakes"];
          allow-import-from-derivation = true;
        };
      })
    ]
    # `lib.optional`, not another mkIf: a definition inside a false mkIf is still
    # a definition as far as the "option does not exist" check is concerned, and
    # `determinateNix` exists on exactly the hosts that import its module.
    ++ lib.optional (options ? determinateNix) (
      lib.mkIf config.determinateNix.enable {
        # Additive forms on purpose. customSettings is written verbatim to
        # nix.custom.conf, so a plain `trusted-public-keys` would replace the
        # built-in cache.nixos.org-1 key rather than merge with it the way the
        # NixOS option does, a plain `substituters` would drop Determinate's own
        # cache.flakehub.com entry, and a plain `trusted-users` would unseat
        # root. `experimental-features` is left out for the same reason:
        # Determinate sets a superset (external-builders, provenance) that this
        # must not truncate.
        determinateNix.customSettings = {
          extra-substituters = substituters;
          extra-trusted-public-keys = publicKeys;
          extra-trusted-users = config.my.host.usernames;
          allow-import-from-derivation = true;
        };
      }
    )
  );
}
