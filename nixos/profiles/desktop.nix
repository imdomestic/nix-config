{ lib, ... }:
{
  imports = [
    ../modules/nerdfonts
    ../modules/fcitx5
  ];

  # Core desktop expectations
  services = {
    displayManager.gdm.enable = lib.mkDefault true;
    desktopManager.gnome.enable = lib.mkDefault true;
  };

  services.pipewire = {
    enable = lib.mkDefault true;
    pulse.enable = lib.mkDefault true;
    jack.enable = lib.mkDefault true;
  };

  services.printing.enable = lib.mkDefault true;

  hardware = {
    bluetooth.enable = lib.mkDefault true;
    # pulseaudio.enable = lib.mkDefault false;
    graphics.enable = lib.mkDefault true;
  };

  programs = {
    zsh.enable = lib.mkDefault true;
    nix-ld.enable = lib.mkDefault true;
  };
}
