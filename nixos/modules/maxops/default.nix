{
  config,
  lib,
  inputs,
  pkgs,
  ...
}: let
  host = config.my.host;
  cfg = host.maxops;
  localHub = host.name == "h610";
  repositoryName =
    if localHub
    then "nix-config"
    else "nix-config-${host.name}";
  deploymentName = "${host.name}-system";
  gaojiDeploymentHost = builtins.elem host.name ["h310" "h610" "tank"];
in {
  imports = [
    inputs.maxops.nixosModules.agent
    inputs.maxops.nixosModules.executor
  ];

  config = lib.mkMerge [
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = host.tsIp != null;
          message = "maxops requires an inventory Tailscale address";
        }
        {
          assertion = cfg.readAllUnits || cfg.readableUnits != [] || cfg.manageableUnits != [];
          message = "maxops requires an explicit observation policy";
        }
      ];

      sops.secrets = {
        "maxops/agent_token" =
          {
            mode = "0400";
            restartUnits = ["maxops-agent.service"] ++ lib.optional localHub "maxops-hub.service";
          }
          // lib.optionalAttrs (!localHub) {
            sopsFile = ../../../secrets/maxops + "/${host.name}.yaml";
            key = "agent_token";
          };
        "maxops/execution_token" =
          {
            mode = "0400";
            restartUnits =
              ["maxops-agent.service"]
              ++ lib.optional localHub "maxops-hub.service";
          }
          // lib.optionalAttrs (!localHub) {
            sopsFile = ../../../secrets/maxops + "/${host.name}.yaml";
            key = "execution_token";
          };
      };

      services.maxops-agent = {
        enable = true;
        hostName = host.name;
        listenAddress =
          if localHub
          then "127.0.0.1"
          else host.tsIp;
        tokenFile = config.sops.secrets."maxops/agent_token".path;
        readAllUnits = cfg.readAllUnits;
        readableUnits = cfg.readableUnits ++ cfg.manageableUnits;
        manageableUnits = cfg.manageableUnits;
        allowLogs = true;
        execution = {
          enable = true;
          tokenFile = config.sops.secrets."maxops/execution_token".path;
        };
      };

      services.maxops-executor = {
        enable = true;
        package = lib.mkIf gaojiDeploymentHost (import ../../../lib/gaoji-ops-package.nix {inherit inputs pkgs;});
        hostName = host.name;
        manageableUnits = cfg.manageableUnits;
        profiles = {
          diagnostic = {
            timeoutSeconds = 7200;
            tasksMax = 512;
            # Nix checks need a writable cache; see docs/incidents.md#maxops-check-cache.
            environment = {
              HOME = "/tmp";
              PATH = lib.makeBinPath [
                pkgs.coreutils
                pkgs.systemd
                pkgs.iproute2
                pkgs.procps
                pkgs.gnugrep
                pkgs.gnused
                pkgs.gawk
                pkgs.findutils
                pkgs.jq
                pkgs.curl
                pkgs.iputils
                pkgs.tailscale
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
        repositories.${repositoryName} = {
          url = "https://github.com/imdomestic/nix-config.git";
          publishRefs = ["refs/heads/main"];
          checks."${host.name}-eval" = [
            "${pkgs.nix}/bin/nix"
            "eval"
            "--raw"
            ".#nixosConfigurations.${host.name}.config.system.build.toplevel.drvPath"
          ];
          authorName = "maxops";
          authorEmail = "maxops@${host.name}";
        };
        deploymentProfiles.${deploymentName} = {
          repository = repositoryName;
          targetHost = host.name;
          flakeAttribute = "nixosConfigurations.${host.name}.config.system.build.toplevel";
          buildProfile = "diagnostic";
          activateProfile = "activation";
          verifyProfile = "diagnostic";
          verifyCommands =
            [
              ["${pkgs.systemd}/bin/systemctl" "is-active" "maxops-agent.service"]
              ["${pkgs.systemd}/bin/systemctl" "is-active" "maxops-executor.service"]
              ["${pkgs.systemd}/bin/systemctl" "is-active" "tailscaled.service"]
              ["${pkgs.systemd}/bin/systemctl" "is-active" "prometheus-node-exporter.service"]
            ]
            ++ lib.optional gaojiDeploymentHost ["${pkgs.systemd}/bin/systemctl" "is-active" "gaoji-cluster-worker.service"];
          automaticRollback = true;
        };
      };

      networking.firewall.interfaces.tailscale0.allowedTCPPorts =
        lib.optional (!localHub) config.services.maxops-agent.port;
    })
  ];
}
