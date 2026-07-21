{
  inputs,
  pkgs,
  config,
  ...
}: {
  # Used for backwards compatibility, please read the changelog before changing.
  # $ darwin-rebuild changelog
  imports = [
    inputs.paneru.darwinModules.paneru
    ../../modules/nerdfonts
    ../../modules/aerospace
    # ../../modules/paneru
  ];
  system.stateVersion = 5;

  system.defaults = {
    dock.autohide = true;
    dock.mru-spaces = false;
    dock.wvous-tl-corner = 5;
    dock.wvous-bl-corner = 14;
    dock.orientation = "bottom";
    dock.magnification = false;
    dock.scroll-to-open = true;
    dock.tilesize = 48;
    finder.AppleShowAllExtensions = true;
    finder.FXPreferredViewStyle = "clmv";
    screencapture.location = "~/Pictures/screenshots";
    screensaver.askForPasswordDelay = 10;
  };

  nix.enable = false;
  nixpkgs.hostPlatform = "aarch64-darwin";

  environment.systemPackages = with pkgs; [
    iproute2mac
    nixos-rebuild
    nixos-rebuild-ng
  ];

  # host-users
  networking.computerName = config.my.host.name;
  system.defaults.smb.NetBIOSName = config.my.host.name;
  system.primaryUser = "hank";

  homebrew = {
    enable = true;
    caskArgs.no_quarantine = true;
    global.brewfile = true;
    casks = [
      "orbstack"
      "cherry-studio"
      "equinox"
    ];
  };

  programs.nix-index-database.comma.enable = true;

  # services.postgresql = {
  #   enable = true;
  #   enableTCPIP = true;
  #   package = pkgs.postgresql_17;
  #   authentication = pkgs.lib.mkOverride 10 ''
  #     #type database  DBuser  auth-method
  #     local all       all     trust
  #   '';
  # };

  networking.wg-quick.interfaces = {
    wg0 = {
      autostart = true;
      address = ["10.0.0.65/24"];
      listenPort = 50722;
      privateKeyFile = "/Users/hank/Documents/privatekey";
      peers = [
        {
          publicKey = "i9ZU3WdqNxUyqtaM9F8Rbrs4ophdNpQ6wZeO/bV/jjQ=";
          presharedKeyFile = "/Users/hank/Documents/presharedkey";
          allowedIPs = ["10.0.0.0/24"];
          endpoint = "sh.imdomestic.com:50722";
          persistentKeepalive = 25;
        }
      ];
    };
  };

  determinateNix = {
    enable = true;
    customSettings = {
      # 数字越小越优先:SJTU 镜像加速 -> 官方源兜底
      substituters = [
        "https://mirror.sjtu.edu.cn/nix-channels/store?priority=10"
        "https://cache.nixos.org?priority=20"
      ];
      extra-substituters = [
        "https://cache.iog.io?priority=40"
      ];
      extra-trusted-public-keys = [
        "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
      ];
      cores = 0;
      eval-cores = 0;
      trusted-users = [
        "root"
        "hank"
      ];
    };
  };

  # environment.etc."nix/registry.json".text = builtins.toJSON {
  #   version = 2;
  #   flakes = [
  #     {
  #       from = {
  #         type = "indirect";
  #         id = "nixpkgs";
  #       };
  #       to = {
  #         type = "path";
  #         path = inputs.nixpkgs.outPath;
  #         lastModified = inputs.nixpkgs.lastModified;
  #         narHash = inputs.nixpkgs.narHash;
  #         rev = inputs.nixpkgs.rev;
  #       };
  #     }
  #   ];
  # };
}
