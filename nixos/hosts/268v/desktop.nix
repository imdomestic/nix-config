{pkgs, ...}: {
  imports = [
    ../../modules/keyd
    ../../modules/nerdfonts
  ];

  i18n.inputMethod.ibus.engines = [pkgs.ibus-engines.libpinyin];
  services = {
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
