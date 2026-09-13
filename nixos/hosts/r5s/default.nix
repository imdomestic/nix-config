{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "aarch64-linux";
  kind = "nixos";
  roles = ["server"];
  tsName = "r5s.inner.imdomestic.com";
  # tank 那一段;tank 的救援 initrd 也在这段上(192.168.20.50)。
  lanRoutes = ["192.168.20.0/24"];
  maxops = {
    enable = true;
    manageableUnits = ["maxops-agent.service" "maxops-executor.service" "tailscaled.service" "prometheus-node-exporter.service" "xray.service" "mihomo.service" "ddns-go.service" "systemd-resolved.service"];
  };
  ip = "10.0.0.9";
  sshUser = "root";

  profiles = with nixosProfiles; [
    base
    server
    netdiag
  ];

  modules = [
    ./system.nix
  ];

  users = {
    nix = {
      home = {
        profiles = with homeProfiles; [
          core
        ];
        modules = [
          userModules.nix.module
        ];
      };
    };

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
