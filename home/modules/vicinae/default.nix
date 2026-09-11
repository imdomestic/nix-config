{pkgs, ...}: {
  programs.vicinae = {
    enable = true;
    systemd.enable = true;
    # GNOME uses the companion extension instead of the layer-shell protocol.
    settings.launcher_window.layer_shell.enabled = false;
  };

  programs.gnome-shell = {
    enable = true;
    extensions = [{package = pkgs.gnomeExtensions.vicinae;}];
  };
}
