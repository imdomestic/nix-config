{
  description = "Hank's fleet: NixOS, nix-darwin, standalone Home Manager and system-manager configurations";

  # Every file under flake/ is a flake-parts module (import-tree), plus each
  # host's registry entry (hosts/<name>/host.nix) and each account's
  # table entry (home/users/<dir>/user.nix). Start at flake/schema/hosts.nix.
  outputs = inputs:
    inputs.flake-parts.lib.mkFlake {inherit inputs;} {
      imports = [
        (inputs.import-tree ./flake)
        (inputs.import-tree.match ".*/host\\.nix" ./hosts)
        (inputs.import-tree.match ".*/user\\.nix" ./home/users)
      ];
    };

  inputs = {
    vex.url = "git+ssh://git@github.com/imdomestic/vex?ref=feat/vex-p2";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    import-tree.url = "github:vic/import-tree";
    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };
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
      # 必须钉在和 nixpkgs 同一个 release 分支上:main 跟的是 nixos-unstable,
      # 它会在求值时直接 throw 拒绝配一个 26.05 的 nixpkgs。
      url = "github:numtide/system-manager/release-26.05";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    llm-agents.url = "github:numtide/llm-agents.nix";

    nix-flatpak.url = "github:gmodena/nix-flatpak/v0.7.0";

    wayland-scroll-factor = {
      url = "github:daniel-g-carrasco/wayland-scroll-factor/v1.0.0";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    llama-swap-proxy = {
      url = "github:emanspeaks/llama-swap-proxy/272260e56f4a47911dd46c5b2adf315df07c9938";
      flake = false;
    };
    opencode-model-stats = {
      url = "github:emanspeaks/opencode-model-stats/e461c45e70412ca491c24f0e0dde3e0a96eaeebf";
      flake = false;
    };

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
      inputs.nixpkgs.follows = "nixpkgs";
    };

    defaulx = {
      url = "github:HCHogan/defaulx";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    max.url = "github:HCHogan/max";

    qq-bot = {
      url = "github:zty20040403/gaojibot";
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

    zjstatus = {
      url = "github:dj95/zjstatus";
    };

    nur = {
      url = "github:nix-community/NUR";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    paneru = {
      url = "github:karinushka/paneru";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    nix-minecraft.url = "github:Infinidoge/nix-minecraft";

    # 运营集群的 k8s 配置用 Nix 写，渲染成 YAML 交给 Argo CD，见 k8s/。
    nixidy = {
      url = "github:arnarg/nixidy/latest";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    thymis.url = "github:Thymis-io/thymis/v0.3";
    steam-servers.url = "github:scottbot95/nix-steam-servers";
  };
}
