# GitHub Actions 构建 + 推 imdomestic.cachix.org 的目标清单。
#
# 只放 cache.nixos.org 一定没有的东西 —— 免费额度就 5G,把 Hydra 已经有的
# 路径推上去纯属浪费。判据是"本地非编不可":自己打的包,以及被 nixos-hardware
# 改过的内核。
#
# deploy-rs 不在这里:它已经改成用 nixpkgs 里 Hydra 构建好的那个二进制了,
# 见 flake/builders/deploy.nix,不需要我们自己编更不需要缓存。
#
# 全部从 **host 自己的 pkgs / config** 里取,而不是 nixpkgs.legacyPackages:
# 这些 host 是带 overlay 的(flake/builders/systems.nix 叠了 nur,modules/nix.nix
# 还有一层),换个 pkgs 实例 callPackage 出来的 drv hash 可能对不上 —— 那样推上去
# 的缓存一条都命不中,CI 白跑。
{config, ...}: let
  nixos = config.flake.nixosConfigurations;
  darwin = config.flake.darwinConfigurations;
  font = cfg: cfg.pkgs.callPackage ../../pkgs/recursive-mono-cascadia-italic {};
  agentSidebar = cfg: cfg.pkgs.callPackage ../../pkgs/tmux-agent-sidebar {};
  templarDroidspacesKernel = cfg: cfg.pkgs.callPackage ../../pkgs/templar-droidspaces-kernel {};
in {
  flake.packages = {
    aarch64-linux = {
      # rpi4 引了 nixos-hardware 的 raspberry-pi-4 模块,内核被改过,drv 是
      # Hydra 从没见过的,每次都得从源码整编 —— 整个缓存里最值钱的一项。
      rpi4-kernel = nixos.rpi4.config.boot.kernelPackages.kernel;
      # smart 分支目前只有 r6s 开着(别的机器用的还是上游 mihomo)。直接取 config
      # 里那个值,保证和 r6s 真正要的是同一个 drv;哪天别的机器也开 smart,
      # 按同样写法往对应 system 下加一条。
      mihomo-smart = nixos.r6s.config.services.mihomo.package;
      # 原生 ARM64 构建入口；只产出 Android Image，不是 NixOS kernelPackages。
      templar-droidspaces-kernel = templarDroidspacesKernel nixos.rpi4;
      # hank 的 home 在每台机器上都一样,所以这个 Rust TUI 会跟到 r2s / rpi4
      # 这种小 ARM 盒子上去 —— 而 home 是 deploy 时在**目标机**上编的
      # (deploy 走 --remote-build)。不缓存的话那几台要现编一遍。
      tmux-agent-sidebar = agentSidebar nixos.rpi4;
    };
    x86_64-linux = {
      cliproxy-rewind = nixos.tank.config.services.cliproxy.rewind.package;
      bonsai-convert-env = nixos.seraph.pkgs.callPackage ../../pkgs/bonsai-convert-env {};
      vfio-igd-rom = nixos."268v".config.my.windowsVM.igdROM;
      # 在 taipan 等 x86_64 Linux 主机上通过 LLVM 构建 ARM64 Android 内核。
      templar-droidspaces-kernel = templarDroidspacesKernel nixos.taipan;
      # taipan / x470 两台解析出来是同一个 drv,取哪台都一样。
      recursive-mono-cascadia-italic = font nixos.taipan;
      tmux-agent-sidebar = agentSidebar nixos.taipan;
    };
    aarch64-darwin = {
      recursive-mono-cascadia-italic = font darwin.praxic;
      tmux-agent-sidebar = agentSidebar darwin.praxic;
    };
    # x86_64-darwin(hackintosh)没进来:macos-13 runner 正在退役,而且 26.05
    # 是 nixpkgs 最后一个支持 x86_64-darwin 的版本,不值得为它单开一条流水线。
  };
}
