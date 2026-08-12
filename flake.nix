{
  description = "Hank's nix configuration for both NixOS & macOS";

  outputs = inputs @ {self, ...}: let
    hosts = import ./nixos/hosts {inherit inputs;};
    systems = (import ./lib/mkConfigurations.nix {inherit inputs;}) {inherit hosts;};
    homes = (import ./lib/mkHomeConfigurations.nix {inherit inputs;}) {inherit hosts;};
    systemManagers = (import ./lib/mkSystemManagerConfigurations.nix {inherit inputs;}) {inherit hosts;};
    deployNodes = (import ./lib/mkDeployNodes.nix {inherit inputs;}) {
      inherit hosts;
      inherit (systems) nixosConfigurations;
      homeConfigurations = homes;
    };
  in {
    inherit (systems) nixosConfigurations darwinConfigurations;
    homeConfigurations = homes;
    systemConfigs = systemManagers;
    hosts = hosts;
    deploy.nodes = deployNodes;

    # GitHub Actions 构建 + 推 imdomestic.cachix.org 的目标清单。
    #
    # 只放 cache.nixos.org 一定没有的东西 —— 免费额度就 5G,把 Hydra 已经有的
    # 路径推上去纯属浪费。判据是"本地非编不可":自己打的包,以及被 nixos-hardware
    # 改过的内核。
    #
    # deploy-rs 不在这里:它已经改成用 nixpkgs 里 Hydra 构建好的那个二进制了,
    # 见 lib/mkDeployNodes.nix,不需要我们自己编更不需要缓存。
    #
    # 全部从 **host 自己的 pkgs / config** 里取,而不是 nixpkgs.legacyPackages:
    # 这些 host 是带 overlay 的(mkConfigurations 叠了 nur,modules/nix.nix 还有
    # 一层),换个 pkgs 实例 callPackage 出来的 drv hash 可能对不上 —— 那样推上去
    # 的缓存一条都命不中,CI 白跑。
    packages = let
      nixos = systems.nixosConfigurations;
      darwin = systems.darwinConfigurations;
      font = cfg: cfg.pkgs.callPackage ./pkgs/recursive-mono-cascadia-italic {};
    in {
      aarch64-linux = {
        # rpi4 引了 nixos-hardware 的 raspberry-pi-4 模块,内核被改过,drv 是
        # Hydra 从没见过的,每次都得从源码整编 —— 整个缓存里最值钱的一项。
        rpi4-kernel = nixos.rpi4.config.boot.kernelPackages.kernel;
        # smart 分支目前只有 r6s 开着(别的机器用的还是上游 mihomo)。直接取 config
        # 里那个值,保证和 r6s 真正要的是同一个 drv;哪天别的机器也开 smart,
        # 按同样写法往对应 system 下加一条。
        mihomo-smart = nixos.r6s.config.services.mihomo.package;
      };
      x86_64-linux = {
        # b650 / x470 两台解析出来是同一个 drv,取哪台都一样。
        recursive-mono-cascadia-italic = font nixos.b650;
      };
      aarch64-darwin = {
        recursive-mono-cascadia-italic = font darwin.m1elite;
      };
      # x86_64-darwin(hackintosh)没进来:macos-13 runner 正在退役,而且 26.05
      # 是 nixpkgs 最后一个支持 x86_64-darwin 的版本,不值得为它单开一条流水线。
    };

    # `nix flake check` validates every deploy node's schema.
    checks =
      builtins.mapAttrs
      (system: deployLib: deployLib.deployChecks self.deploy)
      inputs.deploy-rs.lib;
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";

    nix-index-database.url = "github:nix-community/nix-index-database";
    nix-index-database.inputs.nixpkgs.follows = "nixpkgs";

    # macos
    nix-darwin = {
      url = "github:lnl7/nix-darwin/nix-darwin-26.05";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    determinate.url = "https://flakehub.com/f/DeterminateSystems/determinate/*";

    deploy-rs = {
      url = "github:serokell/deploy-rs";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    nixos-hardware.url = "github:NixOS/nixos-hardware/master";

    nixos-wsl = {
      url = "github:nix-community/NixOS-WSL";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # home manager for managing user config
    home-manager = {
      url = "github:nix-community/home-manager/release-26.05";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    system-manager = {
      url = "github:numtide/system-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # CLIProxyAPI(h610 上把 ChatGPT 订阅包成 OpenAI 兼容 API)。nixpkgs 里没有
    # 这个包,而上游发版极快(2026-07 一个月 64 个 release),自己维护 vendorHash
    # 跟不动;numtide 这个仓库有现成的 derivation 并且跟着上游自动更新。
    #
    # **故意不 follows 我们的 nixpkgs。** follow 之后 Go 工具链和全部依赖都换成
    # 我们这份,derivation hash 跟着变,他们预构建的产物就一个都命不中,等于每次
    # 都在本地从源码编一个 Go 项目。用他们锁的那份 nixpkgs 才能吃到二进制缓存。
    # 代价是多下一份 nixpkgs 求值用的源码(不参与构建,不进 system closure)。
    llm-agents.url = "github:numtide/llm-agents.nix";

    sops-nix = {
      url = "github:Mic92/sops-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    NixVirt = {
      url = "https://flakehub.com/f/AshleyYakeley/NixVirt/*.tar.gz";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    nixvim = {
      url = "github:nix-community/nixvim/nixos-26.05";
      # If you are not running an unstable channel of nixpkgs, select the corresponding branch of Nixvim.
      # url = "github:nix-community/nixvim/nixos-25.11";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # max QQ bot — provides nixosModules.max-bot (h610). Not following
    # our nixpkgs on purpose: its haskell package set is pinned to the
    # 25.11 GHC it was developed against.
    max.url = "github:HCHogan/max";

    qq-bot = {
      url = "github:zty20040403/chat-bot";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    kvim = {
      url = "git+ssh://git@github.com/HCHogan/kvim";
      flake = false;
    };

    hvim = {
      url = "github:HCHogan/hvim";
      flake = false;
    };

    wezterm-config = {
      url = "git+ssh://git@github.com/HCHogan/wezterm";
      flake = false;
    };

    zsh-hank = {
      url = "github:HCHogan/zsh";
      flake = false;
    };

    zsh-linwhite = {
      url = "github:linwh1te/zsh";
      flake = false;
    };

    wg-config = {
      url = "git+ssh://git@github.com/imdomestic/wgconfigs";
      flake = false;
    };

    catppuccin.url = "github:catppuccin/nix";

    zjstatus = {
      url = "github:dj95/zjstatus";
    };

    nur = {
      url = "github:nix-community/NUR";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    quickshell = {
      url = "github:outfoxxed/quickshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    noctalia = {
      url = "github:noctalia-dev/noctalia-shell";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    paneru = {
      url = "github:karinushka/paneru";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    nix-minecraft.url = "github:Infinidoge/nix-minecraft";
    # headplane = {
    #   url = "github:tale/headplane";
    #   inputs.nixpkgs.follows = "nixpkgs";
    # };

    walker.url = "github:abenz1267/walker";

    vscode-server.url = "github:nix-community/nixos-vscode-server";
    thymis.url = "github:Thymis-io/thymis/v0.3";
    steam-servers.url = "github:scottbot95/nix-steam-servers";
    niri.url = "github:sodiboo/niri-flake";
  };
}
