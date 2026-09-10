{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.my.telemetry.gpu;
  inventory = config.my.host.gpuMonitoring;
  settings = pkgs.writeText "gpu-telemetry-settings.json" (builtins.toJSON {
    inherit (inventory) uuids;
    inherit (cfg) temperatureWarning temperatureCritical memoryFreeWarningMiB;
  });
in {
  options.my.telemetry.gpu = {
    temperatureWarning = lib.mkOption {
      type = lib.types.ints.positive;
      default = 83;
      description = "Sustained GPU temperature warning, degrees Celsius.";
    };
    temperatureCritical = lib.mkOption {
      type = lib.types.ints.positive;
      default = 88;
      description = "Sustained critical GPU temperature, degrees Celsius.";
    };
    memoryFreeWarningMiB = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 128;
      description = "Warn below this free VRAM for 15 minutes; 0 disables. Model residency alone is not a fault.";
    };
  };

  config = lib.mkIf inventory.enable {
    assertions = [
      {
        assertion = config.my.telemetry.enable && config.my.host.tsIp != null;
        message = "GPU monitoring requires telemetry and a Tailnet address.";
      }
      {
        assertion = config.hardware.nvidia.enabled;
        message = "GPU monitoring currently requires the native NVIDIA driver.";
      }
      {
        assertion = cfg.temperatureWarning < cfg.temperatureCritical;
        message = "GPU warning temperature must be lower than critical temperature.";
      }
    ];

    services.prometheus.exporters.nvidia-gpu = {
      enable = true;
      listenAddress = config.my.host.tsIp;
      port = 9835;
      openFirewall = false;
      extraFlags = ["--query-field-names=AUTO"];
    };
    networking.firewall.interfaces.tailscale0.allowedTCPPorts = [9835];
    systemd.services.prometheus-nvidia-gpu-exporter = {
      after = ["network-online.target" "tailscaled.service" "nvidia-persistenced.service"];
      wants = ["network-online.target" "tailscaled.service"];
      serviceConfig.RestartSec = "10s";
    };

    # XML, pmon and journal cover fields absent from query-gpu; see docs/gpu-monitoring.md.
    systemd.services.gpu-detail-metrics = {
      description = "NVIDIA detailed telemetry for node exporter";
      after = ["systemd-tmpfiles-setup.service" "nvidia-persistenced.service"];
      path = [config.hardware.nvidia.package.bin pkgs.systemd];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.python3}/bin/python3 ${./gpu-metrics.py} --settings ${settings} --output ${config.my.telemetry.textfileDir}/gpu.prom --state /var/lib/gpu-telemetry/state.json";
        StateDirectory = "gpu-telemetry";
        TimeoutStartSec = "25s";
        UMask = "0022";
        Nice = 10;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = ["AF_UNIX"];
        ReadWritePaths = [config.my.telemetry.textfileDir];
      };
    };
    systemd.timers.gpu-detail-metrics = {
      wantedBy = ["timers.target"];
      timerConfig = {
        OnBootSec = "30s";
        OnUnitInactiveSec = "15s";
        AccuracySec = "1s";
      };
    };
  };
}
