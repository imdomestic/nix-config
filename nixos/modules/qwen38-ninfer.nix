{
  config,
  inputs,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.qwen38Ninfer;
  llamaSwapPort = 8001;

  modelUnitRunner = name: unit:
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = [pkgs.coreutils pkgs.systemd];
      text = ''
        # shellcheck disable=SC2329 # The trap invokes this function indirectly.
        cleanup() {
          systemctl stop ${unit} || true
        }
        trap cleanup EXIT INT TERM

        systemctl start ${unit}
        while systemctl is-active --quiet ${unit}; do
          sleep 1
        done
        exit 1
      '';
    };

  qwen100kRunner = modelUnitRunner "run-qwen38-100k" "podman-qwen38.service";
  qwen262kRunner = modelUnitRunner "run-qwen38-262k" "podman-qwen38-long.service";

  commonModel = {
    checkEndpoint = "/health";
    concurrencyLimit = 1;
    ttl = 0;
    unloadTimeout = 60;
    useModelName = "qwen3.8-27b";
    filters.setParams = {
      return_progress = true;
      timings_per_token = true;
    };
    capabilities = {
      "in" = ["text" "image"];
      "out" = ["text"];
      tools = true;
    };
  };

  llamaSwapSettings = {
    healthCheckTimeout = 300;
    logLevel = "info";
    models = {
      "qwen3.8-27b-fast" =
        commonModel
        // {
          name = "Qwen3.8 27B NVFP4 100K MTP3";
          description = "Native NVFP4 weights and KV cache; 8K vision budget";
          cmd = lib.getExe qwen100kRunner;
          proxy = "http://127.0.0.1:8100";
          metadata = {
            model_type = "vlm";
            context = 100000;
          };
          capabilities = commonModel.capabilities // {context = 100000;};
        };
      "qwen3.8-27b" =
        commonModel
        // {
          name = "Qwen3.8 27B Groupwise INT 262K MTP3";
          description = "Groupwise INT weights and NVFP4 KV cache; 4K vision budget";
          cmd = lib.getExe qwen262kRunner;
          proxy = "http://127.0.0.1:8101";
          metadata = {
            model_type = "vlm";
            context = 262144;
          };
          capabilities = commonModel.capabilities // {context = 262144;};
        };
    };
  };

  llamaSwapConfig = (pkgs.formats.yaml {}).generate "llama-swap-qwen38.yaml" llamaSwapSettings;
  llamaSwapProxy = (pkgs.callPackage inputs.llama-swap-proxy {}).overrideAttrs (old: {
    patches = (old.patches or []) ++ [../hosts/wsl/llama-swap-proxy-backend-timings.patch];
    vendorHash = "sha256-LS+PBnNbtSr3cibu8Nb6DEkko78EVO2l+1hxgsj5Iiw=";
  });

  gatewayRunner = pkgs.writeShellApplication {
    name = "run-qwen38-tailnet-gateway";
    runtimeInputs = [pkgs.coreutils pkgs.tailscale];
    text = ''
      tailnet_address="$(${lib.getExe pkgs.tailscale} ip -4 | head -n 1)"
      if [[ -z "$tailnet_address" ]]; then
        echo "Tailscale has no IPv4 address yet" >&2
        exit 1
      fi

      exec ${lib.getExe llamaSwapProxy} \
        --listen "$tailnet_address:${toString cfg.gatewayPort}" \
        --upstream http://127.0.0.1:${toString llamaSwapPort} \
        --config ${llamaSwapConfig} \
        --sessions-dir ${cfg.stateDirectory}/llama-swap-proxy \
        --default-user hank \
        --opencode-hostname "$tailnet_address:${toString cfg.gatewayPort}"
    '';
  };

  commonContainer = {
    image = cfg.image;
    autoStart = false;
    environment.NO_PROXY = "127.0.0.1,localhost,.inner.imdomestic.com";
    volumes = [
      "${cfg.modelDirectory}:/models:ro"
      "${cfg.logDirectory}:/logs"
    ];
    extraOptions = [
      "--device=nvidia.com/gpu=all"
      "--network=host"
      "--ipc=host"
    ];
  };
in {
  options.services.qwen38Ninfer = {
    enable = lib.mkEnableOption "Qwen3.8 27B NInfer inference gateway";
    image = lib.mkOption {
      type = lib.types.str;
      default = "localhost/ninfer:qwen38-24g-550d0ac-1880c63";
      description = "Locally imported NInfer OCI image reference.";
    };
    stateDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/qwen38";
    };
    modelDirectory = lib.mkOption {
      type = lib.types.str;
      default = "${cfg.stateDirectory}/ninfer-models";
    };
    logDirectory = lib.mkOption {
      type = lib.types.str;
      default = "${cfg.stateDirectory}/ninfer-logs";
    };
    imageArchive = lib.mkOption {
      type = lib.types.str;
      default = "${cfg.stateDirectory}/ninfer-image.tar";
      description = "OCI archive imported on demand when the configured image is absent.";
    };
    gatewayPort = lib.mkOption {
      type = lib.types.port;
      default = 8000;
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.services.tailscale.enable;
        message = "services.qwen38Ninfer requires Tailscale because its gateway binds to the Tailnet address.";
      }
    ];

    hardware.nvidia-container-toolkit.enable = true;
    virtualisation = {
      podman.enable = true;
      oci-containers = {
        backend = "podman";
        containers = {
          qwen38 =
            commonContainer
            // {
              cmd = [
                "ninfer-serve"
                "/models/qwen3_8_27b_nvfp4.ninfer"
                "--model-id"
                "qwen3.8-27b"
                "--host"
                "127.0.0.1"
                "--port"
                "8100"
                "--max-context"
                "100000"
                "--default-max-tokens"
                "100000"
                "--kv-capacity"
                "100000"
                "--max-concurrency"
                "1"
                "--prefill-chunk"
                "1024"
                "--kv-dtype"
                "nvfp4"
                "--device-state-slots"
                "0"
                "--host-state-slots"
                "16"
                "--host-kv-mib"
                "1024"
                "--max-private-continuations"
                "4"
                "--max-shared-prefixes"
                "1"
                "--max-long-anchors-per-continuation"
                "1"
                "--media-cache-mib"
                "256"
                "--media-live-mib"
                "2048"
                "--vision-max-tokens"
                "8192"
                "--spec"
                "mtp"
                "--draft-tokens"
                "3"
                "--lm-head-draft"
                "--preserve-thinking"
                "--request-log-jsonl"
                "/logs/qwen38.jsonl"
              ];
            };
          qwen38-long =
            commonContainer
            // {
              cmd = [
                "ninfer-serve"
                "/models/qwen3_8_27b.ninfer"
                "--model-id"
                "qwen3.8-27b"
                "--host"
                "127.0.0.1"
                "--port"
                "8101"
                "--max-context"
                "262144"
                "--default-max-tokens"
                "262144"
                "--kv-capacity"
                "262144"
                "--max-concurrency"
                "1"
                "--prefill-chunk"
                "1024"
                "--kv-dtype"
                "nvfp4"
                "--device-state-slots"
                "0"
                "--host-state-slots"
                "16"
                "--host-kv-mib"
                "1024"
                "--max-private-continuations"
                "4"
                "--max-shared-prefixes"
                "1"
                "--max-long-anchors-per-continuation"
                "1"
                "--media-cache-mib"
                "256"
                "--media-live-mib"
                "2048"
                "--vision-max-tokens"
                "8192"
                "--spec"
                "mtp"
                "--draft-tokens"
                "3"
                "--lm-head-draft"
                "--preserve-thinking"
                "--request-log-jsonl"
                "/logs/qwen38-long.jsonl"
              ];
            };
        };
      };
    };

    systemd.tmpfiles.rules = [
      "d ${cfg.modelDirectory} 0755 root root -"
      "d ${cfg.logDirectory} 0755 root root -"
      "d ${cfg.stateDirectory}/llama-swap-proxy 0750 llama-swap-proxy llama-swap-proxy -"
    ];

    systemd.services = {
      qwen38-image-import = {
        description = "Import the local NInfer OCI image";
        path = [pkgs.podman];
        script = ''
          if podman image exists ${lib.escapeShellArg cfg.image}; then
            exit 0
          fi
          if [[ ! -r ${lib.escapeShellArg cfg.imageArchive} ]]; then
            echo "Missing NInfer image archive: ${cfg.imageArchive}" >&2
            exit 1
          fi
          podman load --input ${lib.escapeShellArg cfg.imageArchive}
          podman image exists ${lib.escapeShellArg cfg.image}
        '';
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
      };
      podman-qwen38 = {
        after = [
          "network-online.target"
          "nvidia-container-toolkit-cdi-generator.service"
          "qwen38-image-import.service"
        ];
        requires = [
          "nvidia-container-toolkit-cdi-generator.service"
          "qwen38-image-import.service"
        ];
        conflicts = ["podman-qwen38-long.service"];
      };
      podman-qwen38-long = {
        after = [
          "network-online.target"
          "nvidia-container-toolkit-cdi-generator.service"
          "qwen38-image-import.service"
        ];
        requires = [
          "nvidia-container-toolkit-cdi-generator.service"
          "qwen38-image-import.service"
        ];
        conflicts = ["podman-qwen38.service"];
      };
      llama-swap.serviceConfig = {
        DynamicUser = lib.mkForce false;
        User = "root";
        Group = "root";
        PrivateUsers = lib.mkForce false;
        ProtectProc = lib.mkForce "default";
        ProcSubset = lib.mkForce "all";
      };
      llama-swap-proxy = {
        description = "Tailnet OpenAI gateway for llama-swap";
        wantedBy = ["multi-user.target"];
        wants = ["network-online.target" "tailscaled.service"];
        requires = ["llama-swap.service"];
        after = ["network-online.target" "tailscaled.service" "llama-swap.service"];
        serviceConfig = {
          Type = "simple";
          User = "llama-swap-proxy";
          Group = "llama-swap-proxy";
          ExecStart = lib.getExe gatewayRunner;
          Restart = "on-failure";
          RestartSec = 5;
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectHome = true;
          ProtectSystem = "strict";
          ReadWritePaths = ["${cfg.stateDirectory}/llama-swap-proxy"];
        };
      };
    };

    services.llama-swap = {
      enable = true;
      listenAddress = "127.0.0.1";
      port = llamaSwapPort;
      settings = llamaSwapSettings;
    };

    users = {
      groups.llama-swap-proxy = {};
      users.llama-swap-proxy = {
        isSystemUser = true;
        group = "llama-swap-proxy";
      };
    };

    networking.firewall.interfaces.tailscale0.allowedTCPPorts = [cfg.gatewayPort];
  };
}
