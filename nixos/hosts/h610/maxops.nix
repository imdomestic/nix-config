{config, ...}: let
  host = config.my.host;
  readableUnits = [
    "max.service"
    "maxops-agent.service"
    "maxops-hub.service"
    "nginx.service"
    "prometheus.service"
    "alertmanager.service"
    "tailscaled.service"
  ];
in {
  sops.secrets."maxops/agent_token" = {
    mode = "0400";
    restartUnits = ["maxops-agent.service" "maxops-hub.service"];
  };
  sops.secrets."maxops/hank_token" = {
    owner = "hank";
    mode = "0400";
    restartUnits = ["maxops-hub.service"];
  };

  services.maxops-agent = {
    enable = true;
    hostName = host.name;
    # The pilot hub is local; remote agents can use tailnet addresses later.
    listenAddress = "127.0.0.1";
    tokenFile = config.sops.secrets."maxops/agent_token".path;
    inherit readableUnits;
    allowLogs = true;
  };

  services.maxops-hub = {
    enable = true;
    listenAddress = host.tsIp;
    hosts = [
      {
        name = host.name;
        agentUrl = "http://127.0.0.1:${toString config.services.maxops-agent.port}";
        tokenFile = config.sops.secrets."maxops/agent_token".path;
        inherit readableUnits;
      }
    ];
    clients = [
      {
        name = "hank";
        tokenFile = config.sops.secrets."maxops/hank_token".path;
        hosts = [host.name];
        capabilities = ["fleet:read" "host:read" "units:read" "logs:read" "alerts:read"];
      }
    ];
    prometheusUrl = "http://${host.tsIp}:${toString config.my.monitoring.port}";
    alertmanagerUrl = "http://${host.tsIp}:${toString config.my.monitoring.alertmanagerPort}";
  };

  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [config.services.maxops-hub.port];
}
