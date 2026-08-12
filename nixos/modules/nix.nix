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
        zjstatus = inputs.zjstatus.packages.${prev.system}.default;
      })
    ];
    config = {
      allowUnfree = true;
    };
  };

  # nix.optimise.automatic = true;

  # nix.gc = {
  #   automatic = true;
  #   options = "--delete-older-than 1w";
  # };

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
