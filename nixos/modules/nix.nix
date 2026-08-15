{inputs, ...}: {
  # The options below come from nixpkgs' config/nix-channel.nix and
  # config/nix-remote-build.nix, neither of which system-manager imports — hence
  # the split. system-manager hosts take nix-settings.nix on its own, which
  # carries the nix.conf settings and the registry pins.
  imports = [./nix-settings.nix];

  nixpkgs = {
    overlays = [
      inputs.nur.overlays.default
      inputs.nix-minecraft.overlay
      # inputs.headplane.overlays.default
      (final: prev: {
        # `prev.stdenv.hostPlatform.system`,不是 `prev.system`:后者是 nixpkgs
        # 的旧别名,26.05 起求值时会打
        #   evaluation warning: 'system' has been renamed to/replaced by
        #                       'stdenv.hostPlatform.system'
        # 这是本仓库唯一一处触发它的地方(实测在 b650 的求值里冒出来)。
        zjstatus = inputs.zjstatus.packages.${prev.stdenv.hostPlatform.system}.default;
      })
    ];
    config = {
      allowUnfree = true;
    };
  };

  # **不开 optimise。** 它靠把 store 里重复的文件互相硬链接来省空间,代价是
  # 一次全量扫描 + 大量元数据写入。这个 fleet 里一半是 SD/eMMC 启动的板子
  # (r2s/r5s/r6s/rpi4),那种介质按写入量磨损,拿寿命换几个 G 不划算 ——
  # r6s 迁到 SD 卡后根盘还剩 223G,空间根本不是瓶颈。
  # nix.optimise.automatic = true;

  # 这个 fleet 从来没开过 GC —— 实测 r6s 上 `nix-gc`/`nix-optimise` 两个 unit
  # 是 `linked, ignored`(有 unit 文件、没 timer,一次都没跑过),8 代堆着、
  # nix store 11G,而根分区总共才 28G。升 nixpkgs 时 nixos-rebuild 撞 ENOSPC
  # 就是这么来的。
  #
  # 30d 而不是原来注释里写的 1w:generation 是出事时唯一的回退手段,一周太短。
  # 30 天既能压住增长,又留得下足够的回滚余地。
  #
  # randomizedDelaySec 是因为这些机器的 timer 会同时到点 —— h610 上并发的
  # GC 加上正在跑的构建,把内存打满过一次(见 alerts.nix 里 MemoryPressureHigh
  # 那条的注释)。错开来跑。
  nix.gc = {
    automatic = true;
    dates = "weekly";
    options = "--delete-older-than 30d";
    randomizedDelaySec = "45min";
  };

  nix = {
    # **`flake:` 而不是 `${inputs.nixpkgs}`。**
    #
    # 插值那种写法会把整棵 nixpkgs 源码树钉成 system closure 的一个依赖 ——
    # 实测每台机器 196 MiB,链路是 `nixos-system → etc → set-environment →
    # …-source`(里面是 COPYING / CONTRIBUTING.md / doc,整个仓库)。全 fleet
    # 每台都在交这份税,而 `<nixpkgs>` 一年也用不到几次。
    #
    # 这个坑在 registry 那边已经填过了 —— 见 lib/nixpkgs-registry.nix 顶部
    # 关于为什么用 githubRef 而不是 `flake = inputs.nixpkgs` 的那段。同一个
    # 问题在 nixPath 这里漏了。
    #
    # `flake:nixpkgs` 交给 registry 在**使用时**解析,不产生 store 依赖,而
    # registry 里那两条正是钉死到 rev + narHash 的,所以 `<nixpkgs>` 拿到的
    # 还是和这次构建完全一致的那份。
    nixPath = [
      "nixpkgs=flake:nixpkgs"
      "nixpkgs-unstable=flake:nixpkgs-unstable"
    ];
    channel.enable = false;

    # 没有 buildMachines 了(见 lib/mkDeployNodes.nix 的 remoteBuild),留着它
    # 是惰性的 —— 万一以后手动往 /etc/nix/machines 里加东西,不用再打开一次。
    distributedBuilds = true;
  };
}
