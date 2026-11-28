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

  abliteratedRunner = modelUnitRunner "run-qwen38-abliterated" "podman-qwen38-abliterated.service";

  commonModel = {
    checkEndpoint = "/health";
    # Matches NInfer's own pending queue. At 1 llama-swap answers every
    # concurrent request with an instant 429 instead of letting the backend
    # queue it: docs/incidents.md#b650-ninfer-429-not-queued
    concurrencyLimit = 16;
    ttl = 0;
    unloadTimeout = 60;
    useModelName = "qwen3.8-27b";
    # Responses 拒绝这些扩展字段，见 docs/incidents.md#qwen-responses-progress-injection。
    filters.byPath = {
      "/v1/chat/completions".setParams = {
        return_progress = true;
        timings_per_token = true;
      };
      # Qwen 只有初始 system 消息，且没有加密推理表示；见 docs/incidents.md#qwen-codex-cli-responses。
      "/v1/responses" = {
        responsesSystemMessages = true;
        stripParams = "include";
      };
      "/v1/responses/input_tokens" = {
        responsesSystemMessages = true;
        stripParams = "include";
      };
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
      "qwen3.8-27b" =
        commonModel
        // {
          name = "qwen3.8-27b";
          description = "Swift-1.5 ajgazin ablation, NVFP4 weights and KV cache, vision and MTP3";
          useModelName = "qwen3.8-27b";
          cmd = lib.getExe abliteratedRunner;
          proxy = "http://127.0.0.1:8101";
          metadata = {
            model_type = "vlm";
            context = 262144;
          };
          capabilities = commonModel.capabilities // {context = 262144;};
        };
    };
  };

  llamaSwapConfig = (pkgs.formats.yaml {}).generate "llama-swap-qwen38.yaml" config.services.llama-swap.settings;
  llamaSwapProxy = (pkgs.callPackage inputs.llama-swap-proxy {}).overrideAttrs (old: {
    patches = (old.patches or []) ++ [../../hosts/wsl/llama-swap-proxy-backend-timings.patch];
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
        --disable-return-progress-injection \
        --sessions-dir ${cfg.stateDirectory}/llama-swap-proxy \
        --default-user hank \
        --opencode-hostname "$tailnet_address:${toString cfg.gatewayPort}"
    '';
  };

  # 制品自带的模板，另外合并全部 system/developer 消息、把 high 当 xhigh：
  # docs/incidents.md#qwen-template-agent-requests。
  chatTemplate = ./qwen38-chat-template.jinja;

  # NInfer 的启动配置。只剩 Swift 一个制品：docs/decisions.md#taipan-qwen-swift-only。
  # 24 GB 上的取值和实测：docs/incidents.md#taipan-ninfer-40dec5ff。
  ninferConfig = {
    name,
    artifact,
    modelId,
    port,
    maxTokens,
  }:
    (pkgs.formats.toml {}).generate "${name}.toml" {
      model = {
        path = "/models/${artifact}";
        chat_template = "/chat-template.jinja";
        vision = true;
      };
      engine = {
        max_context = 262144;
        kv_dtype = "nvfp4";
        context_capacity = "auto";
        # 0B 时 CUDA Graph 实例化缺显存。
        memory_headroom = "256MiB";
        prefill_chunk = 1024;
        cuda_graph = true;
        # Four active lanes share one pool: docs/incidents.md#b650-swift15-concurrency-four.
        max_concurrency = 4;
        # A queued request waits behind a full-length prefill, and the
        # 30 s default expires it: docs/incidents.md#b650-ninfer-429-not-queued
        max_pending_requests = 16;
        pending_timeout = "600s";
      };
      speculative = {
        backend = "mtp";
        draft_tokens = 3;
        proposal_head = "optimized";
        # serve 默认的 adaptive 让 4 并发吞吐掉一半以上。
        length_policy = "fixed";
      };
      # 默认 1 GiB 时 262K 放不下；512 MiB 单张图上限约 8.5K 视觉 token。
      vision.memory_budget = "512MiB";
      media = {
        cache_capacity = "256MiB";
        live_capacity = "2GiB";
      };
      generation = {
        max_tokens = maxTokens;
        preserve_thinking = true;
      };
      server = {
        host = "127.0.0.1";
        inherit port;
        model_id = modelId;
      };
      logging.request_jsonl = "/logs/${name}.jsonl";
    };

  container = settings: {
    image = cfg.image;
    autoStart = false;
    environment.NO_PROXY = "127.0.0.1,localhost,.inner.imdomestic.com";
    volumes = [
      "${cfg.modelDirectory}:/models:ro"
      "${cfg.logDirectory}:/logs"
      "${chatTemplate}:/chat-template.jinja:ro"
      "${ninferConfig settings}:/config.toml:ro"
    ];
    cmd = ["ninfer-serve" "--config" "/config.toml"];
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
      default = "localhost/ninfer:qwen38-40dec5ff-vision48k";
      description = "NInfer image for the Qwen3.8 artifact; built by scripts/build-qwen38-quasar.sh.";
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
      default = "${cfg.stateDirectory}/ninfer-qwen38-40dec5ff-vision48k.tar";
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
          # Pins: docs/incidents.md#b650-swift15-abliterated.
          qwen38-abliterated = container {
            name = "qwen38-abliterated";
            artifact = "qwen3_8_27b_swift15abl_nvfp4full-dflash2-d52441e7.ninfer";
            modelId = "qwen3.8-27b";
            port = 8101;
            maxTokens = 32768;
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
      podman-qwen38-abliterated = {
        after = [
          "network-online.target"
          "nvidia-container-toolkit-cdi-generator.service"
          "qwen38-image-import.service"
        ];
        requires = [
          "nvidia-container-toolkit-cdi-generator.service"
          "qwen38-image-import.service"
        ];
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
      package = pkgs.llama-swap.overrideAttrs (old: {
        patches =
          (old.patches or [])
          ++ [
            ../../scripts/patches/llama-swap-parameter-defaults.patch
            ../../scripts/patches/llama-swap-responses-system-messages.patch
            ../../scripts/patches/llama-swap-systemone.patch
          ];
      });
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
