{
  inputs,
  config,
  ...
}: {
  # Used for backwards compatibility, please read the changelog before changing.
  # $ darwin-rebuild changelog
  imports = [
    inputs.paneru.darwinModules.paneru
    ../../system/modules/nerdfonts
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

  networking.computerName = config.my.host.name;
  networking.localHostName = config.my.host.name;
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

  security.pam.services.sudo_local = {
    touchIdAuth = true;
    reattach = true; # 在 tmux/screen 里也能用 Touch ID
  };

  determinateNix = {
    enable = true;

    # The registry pins and the nix.conf settings both arrive from
    # system/modules/nix-settings.nix, which routes them here rather than to
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
