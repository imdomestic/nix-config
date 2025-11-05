{ lib, ... }:
{
  imports = [
    ../modules/nerdfonts
    ../modules/fcitx5
  ];

  # Core desktop expectations
  services.xserver = {
    enable = lib.mkDefault true;
    displayManager.gdm.enable = lib.mkDefault false;
    desktopManager.gnome.enable = lib.mkDefault false;
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
    opengl.enable = lib.mkDefault true;
  };

  programs = {
    zsh.enable = lib.mkDefault true;
    nix-ld.enable = lib.mkDefault true;
  };
}
