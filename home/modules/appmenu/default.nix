{pkgs, ...}: {
  programs.gnome-shell = {
    enable = true;
    extensions = [{package = pkgs.callPackage ../../../pkgs/gnome-appmenu {};}];
  };

  dconf.settings."org/gnome/shell/extensions/appmenu" = {
    menu-icon = "distributor-logo-nixos";
    use-real-menus = true;
    lock-to-focused-app = true;
    show-user-switcher = false;
    show-workspace-indicator = false;
    # Control+Space belongs to IBus; Vicinae already provides app search.
    search-shortcut = [];
  };
}
