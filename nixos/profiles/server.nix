{ lib, ... }:
{
  services = {
    xserver.enable = lib.mkDefault false;
    printing.enable = lib.mkDefault false;
  };

  # hardware.pulseaudio.enable = lib.mkDefault false;
  services.pipewire.enable = lib.mkDefault false;

  # Servers often rely on predictable networking
  networking.networkmanager.enable = lib.mkDefault false;
}
