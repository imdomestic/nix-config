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
  tsIp = "100.64.0.13";
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
    # inputs.niri.nixosModules.niri
    inputs.nix-minecraft.nixosModules.minecraft-servers
  ];

  users = {
    fendada = {
      home = {
        profiles = with homeProfiles; [
          core
          # 她自己的 zsh 里有 `ls = "eza --icons"`,而 eza 在 base 里 ——
          # 没有 base 的时候那条别名是坏的,只是没人报过。
          base
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
    kenneth = {
      home = {
        profiles = with homeProfiles; [
          core
          base
        ];
        modules = [
          userModules.kenneth.module
        ];
      };
    };
  };
}
