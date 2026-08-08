{
  inputs,
  lib,
  config,
  ...
}: let
  # tank 的 tailscale 地址。构建机就是它:20 核 / 62 GiB / 12T,而 h610 只有
  # 12 核 / 15 GiB —— 后者今天已经被普通的 `nix flake check` 打到 OOM 两次。
  tankAddr = "100.64.0.4";

  # tank 自己不能把自己列成远程构建机(会 ssh 到自己)。
  isTank = config.my.host.name == "tank";
in {
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
    nixPath = [
      "nixpkgs=${inputs.nixpkgs}"
      "nixpkgs-unstable=${inputs.nixpkgs-unstable}"
    ];
    channel.enable = false;
    distributedBuilds = true;

    # --- 远程构建:把编译推给 tank ---
    #
    # **不需要 sshKey。** 这曾经是唯一的障碍 —— nix-daemon 以 root 发起 ssh,
    # 得有一把 root 能读的私钥,要么走 sops 下发、要么逐台收集主机公钥,两种
    # 都得为每台新机器做一次。Tailscale SSH 把这件事整个消掉了:认证走 tailnet
    # 身份,新机器接进来就能用。
    #
    # 实测(2026-08-08,从 h610):
    #   $ nix store ping --store ssh-ng://root@100.64.0.4
    #   Version: 2.34.7   Trusted: 1
    # `Trusted: 1` 是关键 —— 远程构建要求发起方在对端是 trusted user,否则
    # tank 只能当只读的二进制缓存,不能接收 derivation。
    buildMachines = lib.optionals (!isTank) [
      {
        hostName = tankAddr;
        sshUser = "root";
        # ssh-ng 比老的 ssh 协议快,而且是 nix 现在推荐的。
        protocol = "ssh-ng";

        # **必须带 aarch64-linux。** tank 有 boot.binfmt.emulatedSystems,
        # 而真正慢的恰恰是 r6s/rpi4/r5s/r5sjp 那几台 SBC 的闭包 —— 只写
        # x86_64 的话最该被 offload 的活反而留在本地。
        systems = ["x86_64-linux" "aarch64-linux"];

        # 和 tank 自己的 max-jobs 对齐(见 hosts/tank/system.nix)。
        #
        # 客户端这个数字决定同时开几路远程构建,tank 那边的 max-jobs 决定它
        # 实际并发跑几个 —— 客户端给多了只是在 tank 上排队,没有意义,还让
        # 负载来源更难看清。
        #
        # 6 不是 16:tank 是 E5-2666 v3,**10 物理核 / 20 线程**。nproc 报 20
        # 是线程数,按它配会让并发数比物理核还多一倍,而 ARM 构建全是 QEMU
        # 用户态模拟 —— 纯 CPU 密集、吃执行单元,SMT 在这种负载下增益很小。
        maxJobs = 6;
        speedFactor = 2;
        supportedFeatures = ["nixos-test" "benchmark" "big-parallel" "kvm"];
      }
    ];

    settings = {
      # 让 tank 直接从二进制缓存拉依赖,而不是经发起方转发。不开这个的话
      # 远程构建的所有下载都要绕一圈客户端,tank 那条机房带宽等于白搭。
      builders-use-substitutes = true;
    };
  };

  # nix-daemon 以 root 跑,而 root 的 known_hosts 里没有 tank 的记录。
  # Tailscale SSH 出示的是 tailscaled 自己生成的 host key(不是 sshd 的那把),
  # 所以第一次连接会卡在 host key 校验上 —— 而 daemon 用 BatchMode,不会
  # 交互提问,直接失败。
  #
  # 对 tailnet 网段用 accept-new 是合理的:WireGuard 那层已经做了加密和
  # 对端认证,ssh 的 TOFU 在这里是重复劳动。范围严格限定在 100.64.0.0/10,
  # 不影响其它任何主机。
  programs.ssh.extraConfig = ''
    Host 100.64.*
      StrictHostKeyChecking accept-new
  '';
}
