{
  lib,
  pkgs-unstable,
  ...
}: {
  imports = [
    ../modules/ssh
    # 采集端。模块自己按 my.host.tsIp 决定开不开,所以这里无条件 import ——
    # 没设 tsIp 的 server(n100/aarch64-wsl/x470)会自动跳过。
    ../modules/telemetry
  ];

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
