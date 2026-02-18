{
  lib,
  pkgs-unstable,
  ...
}: {
  services = {
    xserver.enable = lib.mkDefault false;
    printing.enable = lib.mkDefault false;
  };

  services.cockpit = {
    package = pkgs-unstable.cockpit;
    enable = true;
    port = 9090;
    openFirewall = true;
    allowed-origins = ["*"];
    settings = {
      WebService = {
        AllowUnencrypted = true;
      };
    };
  };

  # hardware.pulseaudio.enable = lib.mkDefault false;
  services.pipewire.enable = lib.mkDefault false;

  # Servers often rely on predictable networking
  networking.networkmanager.enable = lib.mkDefault false;
}
