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

    # home manager for managing user config
    home-manager = {
      url = "github:nix-community/home-manager/master";
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

    walker.url = "github:abenz1267/walker";

    daeuniverse.url = "github:daeuniverse/flake.nix";
    vscode-server.url = "github:nix-community/nixos-vscode-server";
    thymis.url = "github:Thymis-io/thymis/v0.3";
    steam-servers.url = "github:scottbot95/nix-steam-servers";
    chaotic.url = "github:chaotic-cx/nyx/nyxpkgs-unstable"; # IMPORTANT
  };

  outputs = inputs
  : let
    mkConfigurations = (import ./lib/mkConfigurations.nix) {inherit inputs;};
    mkHomeConfigurations = (import ./lib/mkHomeConfigurations.nix) {inherit inputs;};
    sys = mkConfigurations {
      configurations = [
        {
          hostname = "H610";
          usernames = ["hank" "genisys"];
          system = "x86_64-linux";
          extraModules = [
            inputs.daeuniverse.nixosModules.dae
            inputs.daeuniverse.nixosModules.daed
            inputs.vscode-server.nixosModules.default
            inputs.steam-servers.nixosModules.default
          ];
        }
        {
          hostname = "b660";
          usernames = ["hank"];
          system = "x86_64-linux";
          extraModules = [
            inputs.catppuccin.nixosModules.catppuccin
            inputs.vscode-server.nixosModules.default
          ];
        }
        {
          hostname = "7540u";
          usernames = ["hank"];
          system = "x86_64-linux";
          extraModules = [
            inputs.nixos-hardware.nixosModules.lenovo-thinkpad-t14s-amd-gen4
            inputs.daeuniverse.nixosModules.dae
            inputs.daeuniverse.nixosModules.daed
            inputs.catppuccin.nixosModules.catppuccin
            inputs.vscode-server.nixosModules.default
            inputs.chaotic.nixosModules.default
          ];
        }
        {
          hostname = "tank";
          usernames = ["hank" "fendada" "linwhite" "genisys"];
          system = "x86_64-linux";
          extraModules = [
            inputs.vscode-server.nixosModules.default
            inputs.chaotic.nixosModules.default
          ];
        }
        {
          hostname = "r5s";
          usernames = ["nix"];
          system = "aarch64-linux";
          extraModules = [
            # inputs.nixos-hardware.nixosModules.friendlyarm-nanopi-r5s
          ];
        }
        {
          hostname = "m3max";
          usernames = ["hank"];
          system = "aarch64-darwin";
        }
        {
          hostname = "hackintosh";
          usernames = ["hank"];
          system = "x86_64-darwin";
        }
        {
          hostname = "rpi4";
          usernames = ["nix"];
          system = "aarch64-linux";
        }
        {
          hostname = "wsl";
          usernames = ["hank"];
          system = "x86_64-linux";
        }
      ];
    };
    hm = mkHomeConfigurations {
      usernames = ["hank" "nix"];
    };
  in {
    nixosConfigurations = sys.nixosConfigurations;
    darwinConfigurations = sys.darwinConfigurations;
    homeConfigurations."hank" = inputs.home-manager.lib.homeManagerConfiguration {
      pkgs = import inputs.nixpkgs {
        system = "x86_64-linux";
        overlays = [
          inputs.nur.overlays.default
        ];
      };
      modules = [
        (import ./home/hank.nix {username = "hank";})
      ];
      extraSpecialArgs = {
        inherit inputs;
        usernames = ["hank"];
        system = "x86_64-linux";
        hostname = "home";
      };
    };
  };
}
