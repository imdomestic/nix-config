{pkgs-unstable, ...}: {
  programs.gnome-shell = {
    enable = true;
    extensions = [{package = pkgs-unstable.gnomeExtensions.top-bar-organizer-plus;}];
  };

  dconf.settings."org/gnome/shell/extensions/top-bar-organizer-plus" = {
    # Move the original workspace indicator, preserving its overview/scroll actions.
    left-box-order = [];
    center-box-order = ["dateMenu"];
    right-box-order = [
      "screenRecording"
      "screenSharing"
      "dwellClick"
      "a11y"
      "keyboard"
      "activities"
      "quickSettings"
    ];
    appindicator-order-mode = "off";
  };
}
