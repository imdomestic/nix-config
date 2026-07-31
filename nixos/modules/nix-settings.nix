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
    "https://cache.garnix.io?priority=30"
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
    "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
    "cache.garnix.io:CTFPyKSLcx5RMJKfLo5EEPUObbA78b0YQ2DTCJXqr9g="
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
