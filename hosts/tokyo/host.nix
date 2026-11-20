{inputs, ...}: {
  hosts.tokyo = {
    system = "x86_64-linux";
    kind = "nixos";
    # "monitor-gateway" = Grafana 的统一入口(nginx 故障转移),不跑 Prometheus。
    # 放在这台是因为它既不是 tank 也不是 h610 —— 入口和它代理的两份处在同一个
    # 故障域就没有意义了。见 system/modules/monitoring/gateway.nix。
    roles = ["server" "monitor-gateway"];
    tsName = "tokyo.inner.imdomestic.com";
    ageKey = "age13cr4s6c0h3fpu7kpsvsym6pkah63gnrqr9ry0cr7ellehthnrupqawax9v";
    clusterControl = {
      enable = true;
      manageableUnits = ["tailscaled.service" "prometheus-node-exporter.service" "nginx.service" "xray.service" "derper.service"];
    };
    sshUser = "root";
    maxTier = "dev";
    buildOn = "tank";

    modules = [
      ./disk-config.nix
    ];

    externalModules = [
      inputs.disko.nixosModules.disko
    ];

    users = {
      # Only linwhite's home needs the dev tier; the others retain interactive.
      fendada.tier = "interactive";
      linwhite.ageKey = "age1mjd25w6an6jdaseuqzeld98wlh4jc365yqtr84c4xazc60nplysqaud8xe";
      hank.tier = "interactive";
      kenneth.tier = "interactive";
    };
  };
}
