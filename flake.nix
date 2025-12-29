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
    };
  in {
    inherit (systems) nixosConfigurations darwinConfigurations;
    homeConfigurations = homes;
    systemConfigs = systemManagers;
    hosts = hosts;
    deploy.nodes = deployNodes;
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # macos
    nix-darwin = {
      url = "github:lnl7/nix-darwin";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    determinate.url = "https://flakehub.com/f/DeterminateSystems/determinate/*";

    nixos-hardware.url = "github:NixOS/nixos-hardware/master";

    nixos-wsl = {
      url = "github:nix-community/NixOS-WSL";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # home manager for managing user config
    home-manager = {
      url = "github:nix-community/home-manager/master";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    system-manager = {
      url = "github:numtide/system-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    zen-browser = {
      url = "github:0xc000022070/zen-browser-flake";
    };

    kvim = {
      url = "git+ssh://git@github.com/HCHogan/kvim";
      flake = false;
    };

    hvim = {
      url = "git@ssh://git@github.com/HCHogan/hvim";
      flake = false;
    };

    wezterm-config = {
      url = "git+ssh://git@github.com/HCHogan/wezterm";
      flake = false;
    };

    zsh-config = {
      url = "github:HCHogan/zsh";
      flake = false;
    };

    dae-config = {
      url = "git+ssh://git@github.com/HCHogan/dae";
      flake = false;
    };

    mihomo-config = {
      url = "git+ssh://git@github.com/HCHogan/mihomo-config";
      flake = false;
    };

    wg-config = {
      url = "git+ssh://git@github.com/imdomestic/wgconfigs";
      flake = false;
    };

    catppuccin.url = "github:catppuccin/nix";

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

    nix-minecraft.url = "github:Infinidoge/nix-minecraft";

    walker.url = "github:abenz1267/walker";

    vscode-server.url = "github:nix-community/nixos-vscode-server";
    thymis.url = "github:Thymis-io/thymis/v0.3";
    steam-servers.url = "github:scottbot95/nix-steam-servers";
    niri.url = "github:sodiboo/niri-flake";
  };
}
