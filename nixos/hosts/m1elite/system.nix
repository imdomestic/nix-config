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

  # 三个都搬走了:iproute2mac 在 home/profiles/dev.nix 的 darwin 分支里本来就有,
  # nixos-rebuild 那两个挂到了 users/hank —— 它们是用来推别的机器的,不是这台
  # Mac 自己要的。
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
      # "cherry-studio"
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

    # The registry pins and the nix.conf settings both arrive from
    # nixos/modules/nix-settings.nix, which routes them here rather than to
    # `nix.registry` / `nix.settings` once Determinate is in charge. Only what is
    # genuinely specific to this machine belongs below.
    customSettings = {
      cores = 0;
      eval-cores = 0;

      # /nix is an explicitly case-sensitive APFS volume. Leaving Darwin's
      # default case hack enabled rewrites colliding Linux paths such as
      # ncurses' terminfo/l to l~nix~case~hack~1. Determinate's external Linux
      # builder then sees the rewritten store and cannot assemble an initrd
      # that references the real terminfo/l path.
      use-case-hack = false;
    };
  };
}
