# The portable half of the Nix configuration: just what ends up in nix.conf.
# Kept separate from nix.nix because system-manager hosts import only nixpkgs'
# config/nix.nix, so `nix.settings` resolves there while `nix.registry` /
# `nixPath` / `channel` / `distributedBuilds` do not. Nothing here may touch
# `nixpkgs.*` either — system-manager instantiates pkgs from the overlays passed
# to makeSystemConfig, and defining `nixpkgs.overlays` on top of that sends the
# module system into infinite recursion via users-groups.nix's `pkgs.shadow`.
{config, ...}: {
  nix.settings = {
    trusted-users = config.my.host.usernames;

    # 数字越小越优先:SJTU 镜像加速 -> 官方源兜底 -> 其余专用 cache
    substituters = [
      "https://mirror.sjtu.edu.cn/nix-channels/store?priority=10"
      "https://cache.nixos.org?priority=20"
      "https://cache.garnix.io?priority=30"
      "https://cache.iog.io?priority=40"
      "https://cache.nixos-cuda.org?priority=50"
    ];
    trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
      "cache.garnix.io:CTFPyKSLcx5RMJKfLo5EEPUObbA78b0YQ2DTCJXqr9g="
      "cache.nixos-cuda.org:74DUi4Ye579gUqzH4ziL9IyiJBlDpMRn9MBN8oNan9M="
    ];
    experimental-features = ["nix-command" "flakes"];
    allow-import-from-derivation = true;
  };
}
