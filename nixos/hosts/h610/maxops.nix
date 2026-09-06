{
  config,
  inputs,
  lib,
  ...
}: let
  host = config.my.host;
  inventory = (import ../../../lib/mkInventory.nix {inherit inputs;}) {
    hosts = import ../. {inherit inputs;};
  };
  managed = lib.filter (entry: entry.maxops.enable or false) inventory;
  hostNames = map (entry: entry.name) managed;
in {
  services.max.maxops = {
    enable = true;
    baseUrl = "http://${host.tsIp}:${toString config.services.maxops-hub.port}";
    tokenFile = config.sops.secrets."maxops/max_token".path;
    allowedGroups = [611798505 650536599];
  };
  sops.secrets =
    lib.listToAttrs (map (entry: {
      name = "maxops/agents/${entry.name}";
      value = {
        sopsFile = ../../../secrets/maxops + "/${entry.name}.yaml";
        key = "agent_token";
        mode = "0400";
        restartUnits = ["maxops-hub.service"];
      };
    }) (lib.filter (entry: entry.name != host.name) managed))
    // {
      "maxops/hank_token" = {
        owner = "hank";
        mode = "0400";
        restartUnits = ["maxops-hub.service"];
      };
      "maxops/max_token" = {
        mode = "0400";
        restartUnits = ["maxops-hub.service" "max.service"];
      };
      "maxops/alert_sink" = {
        sopsFile = ../../../secrets/maxops/alert-sink.yaml;
        key = "token";
        mode = "0400";
        restartUnits = ["max.service" "maxops-hub.service"];
      };
    };
  services.max.maxopsNotifications = {
    enable = true;
    tokenFile = config.sops.secrets."maxops/alert_sink".path;
    groups = [611798505];
    hosts = hostNames;
  };

  services.maxops-hub = {
    enable = true;
    listenAddress = host.tsIp;
    hosts =
      map (entry: {
        name = entry.name;
        agentUrl = "http://${
          if entry.name == host.name
          then "127.0.0.1"
          else entry.tsIp
        }:9720";
        tokenFile =
          if entry.name == host.name
          then config.sops.secrets."maxops/agent_token".path
          else config.sops.secrets."maxops/agents/${entry.name}".path;
        readableUnits = entry.maxops.readableUnits;
      })
      managed;
    clients = [
      {
        name = "max";
        tokenFile = config.sops.secrets."maxops/max_token".path;
        hosts = hostNames;
        capabilities = ["fleet:read" "host:read" "metrics:read" "units:read" "logs:read" "alerts:read"];
      }
      {
        name = "hank";
        tokenFile = config.sops.secrets."maxops/hank_token".path;
        hosts = hostNames;
        capabilities = ["fleet:read" "host:read" "metrics:read" "units:read" "logs:read" "alerts:read"];
      }
    ];
    prometheusUrl = "http://${host.tsIp}:${toString config.my.monitoring.port}";
    alertmanagerUrl = "http://${host.tsIp}:${toString config.my.monitoring.alertmanagerPort}";
    alertIngress = {
      enable = true;
      tokenFile = config.sops.secrets."maxops/alert_ingress".path;
      sinkUrl = "http://127.0.0.1:${toString config.services.max.maxopsNotifications.port}/v1/alerts";
      sinkTokenFile = config.sops.secrets."maxops/alert_sink".path;
    };
  };

  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [config.services.maxops-hub.port];
}
