{inputs, ...}: {
  hosts.h610 = {
    system = "x86_64-linux";
    kind = "nixos";
    inChina = true;
    # 第二份监控。**和 tank 配对的意义全在于故障域不同** —— 2026-08-10 tank 那边
    # 停电一整天,h610 全程在线。放同一个屋子里等于还是一份。
    roles = ["server" "monitor"];
    tsName = "h610.inner.imdomestic.com";
    ageKey = "age1m70ml5ff2cxswwqy8vz8al9ptjd4sfqmmk7mufem9gejgk5t34tqp7v7zr";
    clusterControl = {
      enable = true;
      manageableUnits = [
        "docker-qwen35-sycl.service"
        "qwen35-sycl-warmup.service"
        "gaoji-cluster-control.service"
        "gaoji-cluster-worker.service"
        "gaoji.service"
        "qq-bot-postgres-node.service"
        "docker-napcat.service"
        "nginx.service"
        "prometheus.service"
        "alertmanager.service"
        "tailscaled.service"
      ];
    };
    ip = "10.0.0.5";
    sshUser = "root";

    modules = [
      ./system.nix
      ./tailscale-names.nix
      ./cluster.nix
      ./qwen35-sycl.nix
      ./hardware-configuration.nix
    ];

    externalModules = [
      # inputs.headplane.nixosModules.headplane
      inputs.max.nixosModules.max
      inputs.qq-bot.nixosModules.gaoji
      inputs.qq-bot.nixosModules.cluster-control
      inputs.qq-bot.nixosModules.cluster-worker
      inputs.qq-bot.nixosModules.host-control
    ];

    users = {
      hank = {};
      genisys = {};
      linwhite.tier = "interactive";
      kenneth = {};
      fendada = {};
    };
  };
}
