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
      templarDroidspacesKernel = cfg: cfg.pkgs.callPackage ./pkgs/templar-droidspaces-kernel {};
    in {
      aarch64-linux = {
        # rpi4 引了 nixos-hardware 的 raspberry-pi-4 模块,内核被改过,drv 是
        # Hydra 从没见过的,每次都得从源码整编 —— 整个缓存里最值钱的一项。
        rpi4-kernel = nixos.rpi4.config.boot.kernelPackages.kernel;
        # smart 分支目前只有 r6s 开着(别的机器用的还是上游 mihomo)。直接取 config
        # 里那个值,保证和 r6s 真正要的是同一个 drv;哪天别的机器也开 smart,
        # 按同样写法往对应 system 下加一条。
        mihomo-smart = nixos.r6s.config.services.mihomo.package;
        # 由 Determinate 的原生 aarch64-linux builder 构建。工具链全部来自
        # nixpkgs;这个输出只产出可塞进 boot.img 的 Image,不是 NixOS kernelPackages。
        templar-droidspaces-kernel = templarDroidspacesKernel nixos.rpi4;
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
    ciMatrix = let
      inherit (inputs.nixpkgs) lib;
      # system -> GitHub runner。aarch64-linux 用原生 arm64 runner(公开仓库免费),
      # 不要退回 ubuntu-latest + QEMU —— 理由见 cachix.yml 里那段。
      runners = {
        "x86_64-linux" = "ubuntu-latest";
        "aarch64-linux" = "ubuntu-24.04-arm";
        "aarch64-darwin" = "macos-latest";
      };
    in
      lib.pipe hosts [
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

    # **每台一个 deploy check,而且放在 `deployChecks` 而不是 `checks`。**
    #
    # 放 `checks` 里的话 `nix flake check` 会把它们全求值一遍 —— 那正是原来的
    # 毛病:`deployChecks self.deploy` 吃的是整个 deploy,一个进程里深度展开
    # 9 个节点、35 个 profile(其中约 26 个是 home)。2026-08-15 加了 h310
    # (带 4 个 home)之后越过 runner 的资源线,那个 job 卡在 deploy-schema 上
    # 十几分钟然后被 SIGTERM,CI 连红。见 docs/incidents.md#deploy-schema-timeout。
    #
    # 挪到非标准输出之后,nix 只会说一句 "unknown flake output"(已经在 ci.yml
    # 的警告白名单里,当初为 deploy/hosts/systemConfigs 加的),不再求值它。
    #
    # 真正的验证挪进矩阵 job:那边每台**本来就**求值过自己的 toplevel,顺手验
    # 自己这一个节点几乎是白捡的;而且从"一个大 check"变成"每台一个",哪台坏了
    # 一眼看得出来。代价是每台会多求值自己的 home profile(35 个里约 26 个是
    # home,摊到 9 个节点上每台约 3 个)—— 那反而补上了一个真实缺口:矩阵原本
    # 只验 system 不验 home。
    deployChecks = let
      inherit (inputs.nixpkgs) lib;
    in
      builtins.mapAttrs
      (_system: deployLib:
        lib.concatMapAttrs
        (host: node:
          lib.mapAttrs'
          (name: check: lib.nameValuePair "${name}-${host}" check)
          (deployLib.deployChecks {nodes.${host} = node;}))
        deployNodes)
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
