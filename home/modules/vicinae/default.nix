{
  config,
  lib,
  pkgs,
  ...
}: {
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

  dconf.settings = {
    "org/gnome/settings-daemon/plugins/media-keys".custom-keybindings = [
      "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/vicinae/"
    ];
    "org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/vicinae" = {
      name = "Vicinae";
      command = "${lib.getExe config.programs.vicinae.package} toggle";
      binding = "<Alt>a";
    };
  };
}
