{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  # "monitor-gateway" = Grafana 的统一入口(nginx 故障转移),不跑 Prometheus。
  # 放在这台是因为它既不是 tank 也不是 h610 —— 入口和它代理的两份处在同一个
  # 故障域就没有意义了。见 nixos/modules/monitoring/gateway.nix。
  roles = ["server" "monitor-gateway"];
  tsName = "shanghai.inner.imdomestic.com";
  clusterControl = {
    enable = true;
    manageableUnits = ["tailscaled.service" "prometheus-node-exporter.service" "nginx.service" "xray.service" "derper.service"];
  };
  ip = "10.0.0.1";
  sshUser = "root";

  profiles = with nixosProfiles; [
    base
    server
    # desktop
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
  ];

  externalModules = [
    inputs.nix-minecraft.nixosModules.minecraft-servers
  ];

  users = {
    fendada = {
      home = {
        profiles = with homeProfiles; [
          core
          # 她自己的 zsh 里有 `ls = "eza --icons"`,所以需要 interactive。
          base
          interactive
        ];
        modules = [
          userModules.fendada.module
        ];
      };
    };
    linwhite = {
      home = {
        profiles = with homeProfiles; [
          core
          base
          interactive
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
          interactive
        ];
        modules = [
          userModules.hank.module
        ];
      };
    };
    kenneth = {
      home = {
        profiles = with homeProfiles; [
          core
          base
          interactive
        ];
        modules = [
          userModules.kenneth.module
        ];
      };
    };
  };
}
