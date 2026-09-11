{...}: {
  imports = [../../modules/nerdfonts];

  services = {
    displayManager.gdm = {
      enable = true;
      autoSuspend = false;
    };
    desktopManager.gnome.enable = true;
    pipewire = {
      enable = true;
      alsa.enable = true;
      pulse.enable = true;
    };

    # Mutter must leave the inference GPU alone, including in the GDM greeter.
    udev.extraRules = ''
      SUBSYSTEM=="drm", KERNEL=="card[0-9]*", ATTRS{vendor}=="0x1002", ATTRS{device}=="0x13c0", TAG+="mutter-device-preferred-primary"
      SUBSYSTEM=="drm", KERNEL=="card[0-9]*", ATTRS{vendor}=="0x10de", ATTRS{device}=="0x2b8c", TAG+="mutter-device-ignore"
    '';
  };

  security.rtkit.enable = true;
}
