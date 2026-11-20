{
  inputs,
  pkgs,
  config,
  ...
}: {
  imports = [
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

  nixpkgs.hostPlatform = "x86_64-darwin";

  networking.computerName = config.my.host.name;
  system.defaults.smb.NetBIOSName = config.my.host.name;
  system.primaryUser = "hank";
}
