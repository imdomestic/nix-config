{
  config,
  inputs,
  ...
}: let
  m = config.flake.modules;
in {
  hosts.tokyo = {
    system = "x86_64-linux";
    kind = "nixos";
    # "monitor-gateway" = Grafana 的统一入口(nginx 故障转移),不跑 Prometheus。
    # 放在这台是因为它既不是 tank 也不是 h610 —— 入口和它代理的两份处在同一个
    # 故障域就没有意义了。见 nixos/modules/monitoring/gateway.nix。
    roles = ["server" "monitor-gateway"];
    tsName = "tokyo.inner.imdomestic.com";
    ageKey = "age1cddsqmvytfs97c898mnlncam62v0znxyn8am4zln5xv68gn4z3mqs878u9";
    clusterControl = {
      enable = true;
      manageableUnits = ["tailscaled.service" "prometheus-node-exporter.service" "nginx.service" "xray.service" "derper.service"];
    };
    ip = "10.0.0.1";
    sshUser = "root";
    maxTier = "interactive";
    buildOn = "tank";

    profiles = with m.nixos; [
      base
      server
      # desktop
    ];

    modules = [
      ./system.nix
      ./hardware-configuration.nix
      ./disk-config.nix
    ];

    externalModules = [
      inputs.nix-minecraft.nixosModules.minecraft-servers
      inputs.disko.nixosModules.disko
    ];

    users = {
      # 她自己的 zsh 里有 `ls = "eza --icons"`,所以需要 interactive。
      fendada = {};
      linwhite = {};
      hank = {};
      kenneth = {};
    };
  };
}
