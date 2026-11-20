_: {
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
        "qq-bot-postgres-node.service"
        "docker-napcat.service"
        "nginx.service"
        "prometheus.service"
        "alertmanager.service"
        "tailscaled.service"
      ];
    };
    sshUser = "root";

    modules = [
      ./tailscale-names.nix
      ./qwen35-sycl.nix
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
