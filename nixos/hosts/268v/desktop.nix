{
  config,
  lib,
  pkgs,
  ...
}: {
  imports = [
    ../../modules/keyd
    ../../modules/nerdfonts
  ];

  i18n.inputMethod.ibus.engines = [pkgs.ibus-engines.libpinyin];
  programs.wsf = {
    enable = true;
    gnomePreload = false;
  };
  # Scope the preload to GNOME Shell; loading it needs a fresh desktop session.
  systemd.user.services."org.gnome.Shell@" = {
    overrideStrategy = "asDropin";
    restartIfChanged = false;
    environment = {
      # Inherit the session PATH; see docs/incidents.md#gnome-shell-dropin-path.
      PATH = lib.mkForce null;
      LD_PRELOAD = "${config.programs.wsf.package}/lib/wayland-scroll-factor/libwsf_preload.so";
      WSF_SCROLL_VERTICAL_FACTOR = "0.5";
      WSF_SCROLL_HORIZONTAL_FACTOR = "0.5";
      WSF_PINCH_ZOOM_FACTOR = "1.0";
      WSF_PINCH_ROTATE_FACTOR = "1.0";
    };
  };
  services = {
    flatpak.enable = true;
    displayManager.gdm.enable = true;
    desktopManager.gnome.enable = true;
    pipewire = {
      enable = true;
      alsa.enable = true;
      pulse.enable = true;
    };
    power-profiles-daemon.enable = true;
  };
  security.rtkit.enable = true;
}
