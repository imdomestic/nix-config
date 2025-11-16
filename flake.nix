{
  description = "Hank's nix configuration for both NixOS & macOS";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # macos
    nix-darwin = {
      url = "github:lnl7/nix-darwin";
      inputs.nixpkgs.follows = "nixpkgs";
    };

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
      url = "github:HCHogan/kvim";
      flake = false;
    };

    hvim = {
      url = "github:HCHogan/hvim";
      flake = false;
    };

    wezterm-config = {
      url = "github:HCHogan/wezterm";
      flake = false;
    };

    zsh-config = {
      url = "github:HCHogan/zsh";
      flake = false;
    };

    catppuccin.url = "github:catppuccin/nix";

    dae-config = {
      url = "git+ssh://git@github.com/HCHogan/dae";
      flake = false;
    };

    mihomo-config = {
      url = "git+ssh://git@github.com/HCHogan/mihomo-config";
      flake = false;
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
      inputs.quickshell.follows = "quickshell"; # Use same quickshell version
    };

    walker.url = "github:abenz1267/walker";

    daeuniverse.url = "github:daeuniverse/flake.nix";
    vscode-server.url = "github:nix-community/nixos-vscode-server";
    thymis.url = "github:Thymis-io/thymis/v0.3";
    steam-servers.url = "github:scottbot95/nix-steam-servers";
    chaotic.url = "github:chaotic-cx/nyx/nyxpkgs-unstable"; # IMPORTANT
    niri.url = "github:sodiboo/niri-flake";
  };

  outputs = inputs @ {self, ...}: let
    hosts = import ./nixos/hosts {inherit inputs;};
    systems = (import ./lib/mkConfigurations.nix {inherit inputs;}) {inherit hosts;};
    homes = (import ./lib/mkHomeConfigurations.nix {inherit inputs;}) {inherit hosts;};
    systemManagers = (import ./lib/mkSystemManagerConfigurations.nix {inherit inputs;}) {inherit hosts;};
  in {
    inherit (systems) nixosConfigurations darwinConfigurations;
    homeConfigurations = homes;
    systemConfigs = systemManagers;
    hosts = hosts;
  };
}
