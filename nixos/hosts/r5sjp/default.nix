{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "aarch64-linux";
  kind = "nixos";
  roles = ["server"];
  tsIp = "100.64.0.16";
  # 这台不是该段的网关,只是段里的 DHCP 客户端;回程靠 tailscale 默认的 SNAT。
  lanRoutes = ["10.1.2.0/24"];
  maxops = {
    enable = true;
    manageableUnits = ["maxops-agent.service" "maxops-executor.service" "tailscaled.service" "prometheus-node-exporter.service" "xray.service" "nginx.service" "ddns-go.service" "systemd-resolved.service"];
  };

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

    linwhite = {
      home = {
        profiles = with homeProfiles; [
          core
          base
        ];
        modules = [
          userModules.linwhite.module
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
