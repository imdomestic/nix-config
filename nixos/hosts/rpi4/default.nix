{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "aarch64-linux";
  kind = "nixos";
  roles = ["server"];
  tsName = "rpi4.inner.imdomestic.com";
  # 悉尼公寓。原来是 192.168.20.0/24,和 r5s 撞车,2026-09-13 改到 2 段。
  lanRoutes = ["192.168.2.0/24"];
  clusterControl = {
    enable = true;
    manageableUnits = ["tailscaled.service" "prometheus-node-exporter.service" "xray.service" "mihomo.service" "ddns-go.service" "systemd-resolved.service"];
  };
  ip = "10.0.0.6";
  sshUser = "root";

  profiles = with nixosProfiles; [
    base
    server
    netdiag
    # desktop
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
  ];

  externalModules = [
    inputs.nixos-hardware.nixosModules.raspberry-pi-4
  ];

  users = {
    hank = {
      home = {
        profiles = with homeProfiles; [
          core
          base
        ];
        modules = [
          userModules.hank.module
        ];
      };
    };
  };
}
