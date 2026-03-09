{
  inputs,
  pkgs,
  hostname,
  ...
}: {
  # Used for backwards compatibility, please read the changelog before changing.
  # $ darwin-rebuild changelog
  imports = [
    ../../modules/nerdfonts
    ../../modules/aerospace
  ];
  system.stateVersion = 5;

  system.defaults = {
    dock.autohide = false;
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

  nixpkgs.hostPlatform = "aarch64-darwin";

  environment.systemPackages = with pkgs; [
    iproute2mac
  ];

  # host-users
  networking.hostName = hostname;
  networking.computerName = hostname;
  system.defaults.smb.NetBIOSName = hostname;
  system.primaryUser = "linwhite";

  services.tailscale.enable = true;

  homebrew = {
    enable = true;
    caskArgs.no_quarantine = true;
    global.brewfile = true;
    casks = [
    ];
  };

  nix.enable = false;
}
