{
  config,
  inputs,
  lib,
  pkgs,
  ...
}: let
  host = config.my.host;
  inventory = (import ../../../lib/mkInventory.nix {inherit inputs;}) {
    hosts = import ../. {inherit inputs;};
  };
  managed = lib.filter (entry: entry.maxops.enable or false) inventory;
  remoteManaged = lib.filter (entry: entry.name != host.name) managed;
  hostNames = map (entry: entry.name) managed;
  repositoryName = entry:
    if entry.name == host.name
    then "nix-config"
    else "nix-config-${entry.name}";
  repositoryNames = map repositoryName managed;
  deploymentNames = map (entry: "${entry.name}-system") managed;
  gaojiManagementHosts = ["h310" "h610" "tank"];
  gaojiManaged = lib.filter (entry: builtins.elem entry.name gaojiManagementHosts) managed;
  gaojiWorkers = import ../../../lib/gaoji-workers.nix;
  fullCapabilities = [
    "alerts:read"
    "changes:read"
    "deploy:manage"
    "diagnostics:collect"
    "events:read"
    "exec:run"
    "fleet:read"
    "host:read"
    "jobs:cancel"
    "jobs:read"
    "logs:read"
    "metrics:read"
    "remediations:manage"
    "self:read"
    "units:manage"
    "units:read"
    "workspace:publish"
    "workspace:read"
    "workspace:write"
  ];
  gaojiInventory =
    map (entry: {
      host_id = entry.name;
      label = entry.name;
      architecture = entry.system;
      site = "not-recorded";
      maintainer = "shared-infrastructure";
      permission_source = "nix-config MaxOps registry";
      roles = entry.roles;
      observe = true;
      operate = builtins.elem entry.name gaojiManagementHosts;
      compute = builtins.hasAttr entry.name gaojiWorkers;
      readable_units = entry.maxops.readableUnits ++ entry.maxops.manageableUnits;
      operable_units = lib.optionals (builtins.elem entry.name gaojiManagementHosts) entry.maxops.manageableUnits;
    })
    managed;
in {
  services.max.maxops = {
    enable = true;
    baseUrl = "http://${host.tsIp}:${toString config.services.maxops-hub.port}";
    tokenFile = config.sops.secrets."maxops/max_token".path;
    allowedGroups = [611798505 650536599];
  };
  sops.secrets =
    lib.listToAttrs (map (name: {
      name = "gaoji/workers/${name}";
      value = {
        sopsFile = ../../../secrets/gaoji + "/worker-${name}.yaml";
        key = "worker_token";
        mode = "0400";
        restartUnits = ["gaoji-cluster-control.service"];
      };
    }) ["h310" "tank"])
    // lib.listToAttrs (map (entry: {
        name = "maxops/agents/${entry.name}";
        value = {
          sopsFile = ../../../secrets/maxops + "/${entry.name}.yaml";
          key = "agent_token";
          mode = "0400";
          restartUnits = ["maxops-hub.service"];
        };
      })
      remoteManaged)
    // lib.listToAttrs (map (entry: {
        name = "maxops/executors/${entry.name}";
        value = {
          sopsFile = ../../../secrets/maxops + "/${entry.name}.yaml";
          key = "execution_token";
          mode = "0400";
          restartUnits = ["maxops-hub.service"];
        };
      })
      remoteManaged)
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
      "maxops/kennethbot_token" = {
        sopsFile = ../../../secrets/maxops/kennethbot.yaml;
        key = "maxops_token";
        mode = "0400";
        restartUnits = ["maxops-hub.service" "gaoji-cluster-control.service"];
      };
      "kennethbot/cluster_control_token" = {
        sopsFile = ../../../secrets/maxops/kennethbot.yaml;
        key = "control_token";
        mode = "0400";
        restartUnits = ["gaoji-cluster-control.service" "gaoji.service"];
      };
      "gaoji/ops_management_token" = {
        sopsFile = ../../../secrets/maxops/kennethbot.yaml;
        key = "management_token";
        mode = "0400";
        restartUnits = ["maxops-hub.service" "gaoji-cluster-control.service"];
      };
      "gaoji/authorization_key" = {
        sopsFile = ../../../secrets/gaoji/account-auth.yaml;
        key = "authorization_key";
        mode = "0400";
        restartUnits = ["gaoji.service"];
      };
      "gaoji/onebot_access_token" = {
        sopsFile = ../../../secrets/gaoji/account-auth.yaml;
        key = "onebot_access_token";
        mode = "0400";
        restartUnits = ["gaoji.service" "docker-napcat-chat-bot.service"];
      };
      "gaoji/onebot_secret" = {
        sopsFile = ../../../secrets/gaoji/account-auth.yaml;
        key = "onebot_secret";
        mode = "0400";
        restartUnits = ["gaoji.service"];
      };
      "kennethbot/worker_token" = {
        sopsFile = ../../../secrets/maxops/kennethbot-worker.yaml;
        key = "worker_token";
        mode = "0400";
        restartUnits = [
          "gaoji-cluster-control.service"
          "gaoji-cluster-worker.service"
        ];
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
    package = import ../../../lib/gaoji-ops-package.nix {inherit inputs pkgs;};
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
        executionTokenFile =
          if entry.name == host.name
          then config.sops.secrets."maxops/execution_token".path
          else config.sops.secrets."maxops/executors/${entry.name}".path;
        readAllUnits = entry.maxops.readAllUnits;
        readableUnits = entry.maxops.readableUnits ++ entry.maxops.manageableUnits;
        manageableUnits = entry.maxops.manageableUnits;
        diagnosticProfile = "diagnostic";
        diagnosticProbes = {
          failed-units = [
            "/run/current-system/sw/bin/systemctl"
            "--failed"
            "--no-legend"
          ];
          store-space = [
            "/run/current-system/sw/bin/df"
            "-h"
            "/nix/store"
          ];
        };
      })
      managed;
    clients = [
      {
        name = "max";
        tokenFile = config.sops.secrets."maxops/max_token".path;
        hosts = hostNames;
        access = "manage";
        capabilities = fullCapabilities;
        repositories = repositoryNames;
        deployments = deploymentNames;
      }
      {
        name = "hank";
        tokenFile = config.sops.secrets."maxops/hank_token".path;
        hosts = hostNames;
        access = "manage";
        capabilities = fullCapabilities;
        repositories = repositoryNames;
        deployments = deploymentNames;
      }
      {
        name = "kennethbot";
        tokenFile = config.sops.secrets."maxops/kennethbot_token".path;
        hosts = hostNames;
        capabilities = [
          "fleet:read"
          "host:read"
          "metrics:read"
          "units:read"
          "logs:read"
          "alerts:read"
          "events:read"
          "self:read"
        ];
      }
      {
        name = "gaoji-admin";
        tokenFile = config.sops.secrets."gaoji/ops_management_token".path;
        hosts = gaojiManagementHosts;
        access = "manage";
        capabilities = fullCapabilities;
        repositories = map repositoryName gaojiManaged;
        deployments = map (entry: "${entry.name}-system") gaojiManaged;
      }
    ];
    repositories =
      map (entry: {
        name = repositoryName entry;
        executorHost = entry.name;
      })
      managed;
    deployments =
      map (entry: {
        name = "${entry.name}-system";
        repository = repositoryName entry;
        builderHost = entry.name;
        targetHost = entry.name;
        flakeAttribute = "nixosConfigurations.${entry.name}.config.system.build.toplevel";
      })
      managed;
    prometheusUrl = "http://${host.tsIp}:${toString config.my.monitoring.port}";
    alertmanagerUrl = "http://${host.tsIp}:${toString config.my.monitoring.alertmanagerPort}";
    alertIngress = {
      enable = true;
      tokenFile = config.sops.secrets."maxops/alert_ingress".path;
      sinkUrl = "http://127.0.0.1:${toString config.services.max.maxopsNotifications.port}/v1/alerts";
      sinkTokenFile = config.sops.secrets."maxops/alert_sink".path;
    };
  };

  services.maxops-executor.deploymentProfiles.h610-system.verifyCommands = lib.mkAfter [
    ["${pkgs.systemd}/bin/systemctl" "is-active" "maxops-hub.service"]
    ["${pkgs.systemd}/bin/systemctl" "is-active" "max.service"]
    ["${pkgs.systemd}/bin/systemctl" "is-active" "gaoji-cluster-control.service"]
    ["${pkgs.systemd}/bin/systemctl" "is-active" "gaoji.service"]
    ["${pkgs.systemd}/bin/systemctl" "is-active" "prometheus.service"]
    ["${pkgs.systemd}/bin/systemctl" "is-active" "alertmanager.service"]
    ["${pkgs.curl}/bin/curl" "--fail" "--silent" "http://${host.tsIp}:${toString config.services.maxops-hub.port}/readyz"]
  ];

  services.gaoji-host-control = {
    enable = true;
    hostId = host.name;
  };
  services.gaoji-cluster-control = {
    enable = true;
    stateDirectory = "kennethbot-cluster-control";
    environmentFile = config.sops.templates."qq-deepseek-bot-postgres.env".path;
    apiTokenFile = config.sops.secrets."kennethbot/cluster_control_token".path;
    listenAddress = host.tsIp;
    openFirewall = true;
    firewallInterfaces = ["tailscale0"];
    inventory = gaojiInventory;
    hostControlHelpers = lib.genAttrs gaojiManagementHosts (_: "/run/current-system/sw/bin/gaoji-host-control");
    ops = {
      enable = true;
      baseUrl = "http://${host.tsIp}:${toString config.services.maxops-hub.port}";
      tokenFile = config.sops.secrets."maxops/kennethbot_token".path;
      management = {
        enable = true;
        tokenFile = config.sops.secrets."gaoji/ops_management_token".path;
        hosts = gaojiManagementHosts;
        actors = ["qq:3526452465" "admin:kenneth"];
      };
    };
    workers = map (name: {
      workerId = "${name}-worker";
      hostId = name;
      ownerAliases = ["qq:3526452465"];
      tokenFile =
        if name == "h610"
        then config.sops.secrets."kennethbot/worker_token".path
        else config.sops.secrets."gaoji/workers/${name}".path;
    }) (builtins.attrNames gaojiWorkers);
    deployments.repositories = [
      {
        repositoryId = "nix-config";
        backend = "ops";
        url = "https://github.com/imdomestic/nix-config.git";
        allowedChanges = ["system"];
        targets =
          map (entry: {
            hostId = entry.name;
            flakeHost = entry.name;
            opsRepository = repositoryName entry;
            opsProfile = "${entry.name}-system";
            verificationUnits =
              ["maxops-agent.service" "maxops-executor.service" "gaoji-cluster-worker.service"]
              ++ lib.optionals (entry.name == "h610") ["gaoji.service" "gaoji-cluster-control.service" "maxops-hub.service"];
          })
          gaojiManaged;
      }
    ];
    diagnostics.targets =
      map (entry: {
        target_id = "${entry.name}-worker";
        label = "${entry.name} gaoji Worker";
        kind = "service";
        url = "http://${entry.tsIp}:8092/health";
        observer_host = "h610";
        host_id = entry.name;
        service_ref = "gaoji-cluster-worker.service";
      })
      gaojiManaged;
  };

  services.gaoji-cluster-worker = {
    enable = true;
    stateDirectory = "kennethbot-cluster-worker";
    workerId = "h610-worker";
    controlUrl = "http://${host.tsIp}:${toString config.services.gaoji-cluster-control.port}";
    tokenFile = config.sops.secrets."kennethbot/worker_token".path;
    listenAddress = host.tsIp;
    publicBaseUrl = "http://${host.tsIp}:${toString config.services.gaoji-cluster-worker.port}";
    cpuMillis = 2000;
    memoryBytes = 2 * 1024 * 1024 * 1024;
    concurrency = 2;
  };

  services.gaoji.cluster = {
    enable = true;
    controlUrl = "http://${host.tsIp}:${toString config.services.gaoji-cluster-control.port}";
    tokenFile = config.sops.secrets."kennethbot/cluster_control_token".path;
    allowedGroups = [611798505 650536599];
    logAllowedGroups = [];
  };

  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [
    config.services.maxops-hub.port
    config.services.gaoji-cluster-worker.port
  ];
}
