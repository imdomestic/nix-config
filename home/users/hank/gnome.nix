{
  config,
  lib,
  pkgs,
  ...
}: let
  workspaceKeys = lib.listToAttrs (lib.concatMap (n: let
    key =
      if n == 10
      then "0"
      else toString n;
  in [
    (lib.nameValuePair "switch-to-workspace-${toString n}" ["<Alt>${key}"])
    (lib.nameValuePair "move-to-workspace-${toString n}" ["<Alt><Shift>${key}"])
  ]) (lib.range 1 10));
in {
  imports = [
    ../../modules/forge
    ../../modules/ghostty
    ../../modules/vicinae
  ];

  programs.gnome-shell.extensions = [
    {package = pkgs.gnomeExtensions.blur-my-shell;}
    {package = pkgs.gnomeExtensions.just-perfection;}
  ];
  xdg.terminal-exec = {
    enable = true;
    settings.default = ["com.mitchellh.ghostty.desktop"];
  };

  dconf.settings = {
    "org/gnome/mutter" = {
      dynamic-workspaces = false;
      center-new-windows = true;
      edge-tiling = false;
    };
    "org/gnome/desktop/wm/preferences".num-workspaces = 10;
    "org/gnome/desktop/wm/keybindings" =
      workspaceKeys
      // {
        toggle-fullscreen = ["<Alt>f"];
      };
    "org/gnome/settings-daemon/plugins/power" = {
      sleep-inactive-ac-type = "nothing";
      sleep-inactive-battery-type = "nothing";
    };
    "org/gnome/settings-daemon/plugins/media-keys".custom-keybindings = [
      "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/terminal/"
    ];
    "org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/terminal" = {
      name = "Terminal";
      command = lib.getExe config.programs.ghostty.package;
      binding = "<Alt>Return";
    };
    "org/gnome/shell/extensions/forge" = {
      focus-border-toggle = false;
      split-border-toggle = false;
      window-gap-size = lib.hm.gvariant.mkUint32 10;
      resize-amount = lib.hm.gvariant.mkUint32 50;
    };
    "org/gnome/shell/extensions/just-perfection".workspace-popup = false;
    "org/gnome/shell/extensions/forge/keybindings" = {
      window-focus-left = ["<Alt>h"];
      window-focus-down = ["<Alt>j"];
      window-focus-up = ["<Alt>k"];
      window-focus-right = ["<Alt>l"];
      window-move-left = ["<Alt><Shift>h"];
      window-move-down = ["<Alt><Shift>j"];
      window-move-up = ["<Alt><Shift>k"];
      window-move-right = ["<Alt><Shift>l"];
      con-stacked-layout-toggle = ["<Alt>s"];
      con-tabbed-layout-toggle = ["<Alt>w"];
      con-split-layout-toggle = ["<Alt>e"];
      window-toggle-float = ["<Alt><Shift>space"];
      window-resize-right-decrease = ["<Alt>Left"];
      window-resize-right-increase = ["<Alt>Right"];
      window-resize-bottom-increase = ["<Alt>Up"];
      window-resize-bottom-decrease = ["<Alt>Down"];
    };
  };
}
