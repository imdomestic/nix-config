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
  hostNames = map (entry: entry.name) managed;
  # 完整执行面先只落在 h610，见 docs/decisions.md#maxops-h610-full-control。
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
  localManageableUnits = host.maxops.readableUnits;
  kennethbotInventory =
    map (entry: {
      host_id = entry.name;
      label = entry.name;
      architecture = entry.system;
      site = "not-recorded";
      maintainer = "shared-infrastructure";
      permission_source = "nix-config MaxOps registry";
      roles = entry.roles;
      observe = true;
      operate = false;
      compute = entry.name == host.name;
      readable_units = entry.maxops.readableUnits;
      operable_units = [];
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
      "maxops/execution_token" = {
        mode = "0400";
        restartUnits = ["maxops-agent.service" "maxops-hub.service"];
      };
      "maxops/kennethbot_token" = {
        sopsFile = ../../../secrets/maxops/kennethbot.yaml;
        key = "maxops_token";
        mode = "0400";
        restartUnits = ["maxops-hub.service" "kennethbot-cluster-control.service"];
      };
      "kennethbot/cluster_control_token" = {
        sopsFile = ../../../secrets/maxops/kennethbot.yaml;
        key = "control_token";
        mode = "0400";
        restartUnits = ["kennethbot-cluster-control.service" "qq-deepseek-bot.service"];
      };
      "kennethbot/worker_token" = {
        sopsFile = ../../../secrets/maxops/kennethbot-worker.yaml;
        key = "worker_token";
        mode = "0400";
        restartUnits = [
          "kennethbot-cluster-control.service"
          "kennethbot-cluster-worker.service"
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
          else null;
        readableUnits = entry.maxops.readableUnits;
        manageableUnits =
          if entry.name == host.name
          then localManageableUnits
          else [];
        diagnosticProfile =
          if entry.name == host.name
          then "diagnostic"
          else null;
        diagnosticProbes =
          if entry.name == host.name
          then {
            failed-units = [
              "${pkgs.systemd}/bin/systemctl"
              "--failed"
              "--no-legend"
            ];
            store-space = [
              "${pkgs.coreutils}/bin/df"
              "-h"
              "/nix/store"
            ];
          }
          else {};
      })
      managed;
    clients = [
      {
        name = "max";
        tokenFile = config.sops.secrets."maxops/max_token".path;
        hosts = hostNames;
        access = "manage";
        capabilities = fullCapabilities;
        repositories = ["nix-config"];
        deployments = ["h610-system"];
      }
      {
        name = "hank";
        tokenFile = config.sops.secrets."maxops/hank_token".path;
        hosts = hostNames;
        access = "manage";
        capabilities = fullCapabilities;
        repositories = ["nix-config"];
        deployments = ["h610-system"];
      }
      {
        name = "kennethbot";
        tokenFile = config.sops.secrets."maxops/kennethbot_token".path;
        hosts = hostNames;
        capabilities = [
          "fleet:read"
          "host:read"
          "units:read"
          "logs:read"
          "alerts:read"
          "events:read"
          "self:read"
        ];
      }
    ];
    repositories = [
      {
        name = "nix-config";
        executorHost = host.name;
      }
    ];
    deployments = [
      {
        name = "h610-system";
        repository = "nix-config";
        builderHost = host.name;
        targetHost = host.name;
        flakeAttribute = "nixosConfigurations.h610.config.system.build.toplevel";
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

  services.maxops-agent = {
    manageableUnits = localManageableUnits;
    execution = {
      enable = true;
      tokenFile = config.sops.secrets."maxops/execution_token".path;
    };
  };

  services.maxops-executor = {
    enable = true;
    hostName = host.name;
    manageableUnits = localManageableUnits;
    profiles = {
      diagnostic = {
        timeoutSeconds = 7200;
        tasksMax = 512;
        # Nix checks need a writable cache; see docs/incidents.md#maxops-check-cache.
        environment = {
          HOME = "/tmp";
          PATH = lib.makeBinPath [
            pkgs.coreutils
            pkgs.git
            pkgs.nix
          ];
          XDG_CACHE_HOME = "/tmp/.cache";
        };
      };
      operator = {
        user = "root";
        privileged = true;
        timeoutSeconds = 3600;
        workingRoots = ["/"];
        environment = {
          HOME = "/root";
          PATH = "/run/current-system/sw/bin:/run/wrappers/bin";
        };
      };
      activation = {
        user = "root";
        privileged = true;
        timeoutSeconds = 1800;
      };
    };
    repositories.nix-config = {
      url = "https://github.com/imdomestic/nix-config.git";
      publishRefs = ["refs/heads/main"];
      checks = {
        flake-check = [
          "${pkgs.nix}/bin/nix"
          "flake"
          "check"
          "--no-build"
        ];
        h610-eval = [
          "${pkgs.nix}/bin/nix"
          "eval"
          "--raw"
          ".#nixosConfigurations.h610.config.system.build.toplevel.drvPath"
        ];
      };
      authorName = "maxops";
      authorEmail = "maxops@h610";
    };
    deploymentProfiles.h610-system = {
      repository = "nix-config";
      targetHost = host.name;
      flakeAttribute = "nixosConfigurations.h610.config.system.build.toplevel";
      buildProfile = "diagnostic";
      activateProfile = "activation";
      verifyProfile = "diagnostic";
      verifyCommands = [
        ["${pkgs.systemd}/bin/systemctl" "is-active" "maxops-hub.service"]
        ["${pkgs.systemd}/bin/systemctl" "is-active" "maxops-agent.service"]
        ["${pkgs.systemd}/bin/systemctl" "is-active" "maxops-executor.service"]
        ["${pkgs.systemd}/bin/systemctl" "is-active" "max.service"]
        ["${pkgs.systemd}/bin/systemctl" "is-active" "kennethbot-cluster-control.service"]
        ["${pkgs.systemd}/bin/systemctl" "is-active" "qq-deepseek-bot.service"]
        ["${pkgs.systemd}/bin/systemctl" "is-active" "prometheus.service"]
        ["${pkgs.systemd}/bin/systemctl" "is-active" "alertmanager.service"]
        ["${pkgs.curl}/bin/curl" "--fail" "--silent" "http://${host.tsIp}:${toString config.services.maxops-hub.port}/readyz"]
      ];
      automaticRollback = true;
    };
  };

  services.kennethbot-cluster-control = {
    enable = true;
    environmentFile = config.sops.templates."qq-deepseek-bot-postgres.env".path;
    apiTokenFile = config.sops.secrets."kennethbot/cluster_control_token".path;
    inventory = kennethbotInventory;
    maxops = {
      enable = true;
      baseUrl = "http://${host.tsIp}:${toString config.services.maxops-hub.port}";
      tokenFile = config.sops.secrets."maxops/kennethbot_token".path;
    };
    workers = [
      {
        workerId = "h610-worker";
        hostId = host.name;
        tokenFile = config.sops.secrets."kennethbot/worker_token".path;
      }
    ];
  };

  services.kennethbot-cluster-worker = {
    enable = true;
    workerId = "h610-worker";
    controlUrl = "http://127.0.0.1:${toString config.services.kennethbot-cluster-control.port}";
    tokenFile = config.sops.secrets."kennethbot/worker_token".path;
    listenAddress = host.tsIp;
    publicBaseUrl = "http://${host.tsIp}:${toString config.services.kennethbot-cluster-worker.port}";
    cpuMillis = 2000;
    memoryBytes = 2 * 1024 * 1024 * 1024;
    concurrency = 2;
  };

  services.qq-deepseek-bot.cluster = {
    enable = true;
    tokenFile = config.sops.secrets."kennethbot/cluster_control_token".path;
    allowedGroups = [611798505 650536599];
    logAllowedGroups = [];
  };

  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [
    config.services.maxops-hub.port
    config.services.kennethbot-cluster-worker.port
  ];
}
