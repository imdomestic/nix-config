{inputs, ...}: {
  hosts.tank = {
    system = "x86_64-linux";
    kind = "nixos";
    inChina = true;
    # "monitor" = 在这台上跑一份完整监控(Prometheus + Alertmanager + Grafana)。
    # 见 system/modules/monitoring —— 这个角色同时决定本机的开关、对端 Alertmanager
    # 的 gossip 名单、以及"另一份挂了"那条告警的预期成员数。
    roles = ["server" "monitor" "vm-host"];
    tsName = "tank.inner.imdomestic.com";
    ageKey = "age168k3d2228fxjdf6936pwvyzmm6hus9cet06kr64ecgcl6dg4tvrqlqc5hs";
    clusterControl = {
      enable = true;
      manageableUnits = ["tailscaled.service" "prometheus-node-exporter.service" "nginx.service" "prometheus.service" "alertmanager.service" "grafana.service" "samba-smbd.service" "nfs-server.service" "postgresql.service" "matrix-synapse.service" "gaoji-cluster-worker.service"];
    };
    ip = "10.0.0.66";
    sshUser = "root";

    modules = [
      ./k3s.nix
      ./vex-archive.nix
      ./gaoji.nix
      ./gaoji-web.nix
      ./maxx.nix
      ../../system/modules/gaoji-worker.nix
    ];

    externalModules = [
      inputs.maxx.nixosModules.maxx
      inputs.qq-bot.nixosModules.gaoji
      inputs.nix-minecraft.nixosModules.minecraft-servers
      inputs.nix-index-database.nixosModules.default
    ];

    users = {
      hank = {};
      # 她自己的 zsh 里有 `ls = "eza --icons"`,所以需要 interactive。
      fendada = {};
      linwhite = {};
      kenneth = {};
      genisys = {};
    };
  };
}
