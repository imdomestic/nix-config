{
  config,
  lib,
  pkgs,
  ...
}: let
  sourceModel = "clef:27b-q4_K_M";
  model = "clef-27b-4k";
  port = 11434;
  stateDirectory = "/var/lib/clef-ollama";
  initialize = pkgs.writeShellApplication {
    name = "initialize-clef-ollama";
    runtimeInputs = [pkgs.curl pkgs.podman];
    text = ''
      curl --fail --silent --show-error --retry 30 --retry-connrefused --retry-delay 1 \
        http://127.0.0.1:${toString port}/api/version
      if ! podman exec clef ollama show ${lib.escapeShellArg sourceModel} >/dev/null 2>&1; then
        podman exec clef ollama pull ${lib.escapeShellArg sourceModel}
      fi
      # The upstream model's num_ctx overrides OLLAMA_CONTEXT_LENGTH.
      curl --fail --silent --show-error \
        http://127.0.0.1:${toString port}/api/create \
        --json ${lib.escapeShellArg (builtins.toJSON {
        inherit model;
        from = sourceModel;
        parameters.num_ctx = 4096;
        stream = false;
      })}
    '';
  };
  runner = pkgs.writeShellApplication {
    name = "run-clef-ollama";
    runtimeInputs = [pkgs.coreutils pkgs.systemd];
    text = ''
      # shellcheck disable=SC2329 # The trap invokes this function indirectly.
      cleanup() {
        systemctl stop podman-clef.service || true
      }
      trap cleanup EXIT INT TERM
      systemctl start podman-clef.service
      while systemctl is-active --quiet podman-clef.service; do
        sleep 1
      done
      exit 1
    '';
  };
in {
  assertions = [
    {
      assertion = config.services.qwen38Ninfer.enable;
      message = "Clef uses the Qwen llama-swap gateway to share the 24 GB GPU.";
    }
  ];

  virtualisation.oci-containers.containers.clef = {
    image = "docker.io/ollama/ollama:0.40.4@sha256:926d40fd6eeeebd346b5c358a63de2a10ec995371cd93dd22f1843200694b1a6";
    autoStart = false;
    environment = {
      OLLAMA_HOST = "127.0.0.1:${toString port}";
      OLLAMA_MODELS = "/models";
      OLLAMA_CONTEXT_LENGTH = "4096";
      OLLAMA_NUM_PARALLEL = "1";
      OLLAMA_MAX_LOADED_MODELS = "1";
      OLLAMA_KEEP_ALIVE = "-1";
      OLLAMA_FLASH_ATTENTION = "1";
      OLLAMA_NO_CLOUD = "1";
    };
    volumes = ["${stateDirectory}:/models"];
    extraOptions = [
      "--device=nvidia.com/gpu=all"
      "--network=host"
      "--ipc=host"
    ];
  };

  systemd.tmpfiles.rules = ["d ${stateDirectory} 0750 root root -"];
  systemd.services.podman-clef = {
    after = ["network-online.target" "nvidia-container-toolkit-cdi-generator.service"];
    requires = ["nvidia-container-toolkit-cdi-generator.service"];
    postStart = lib.getExe initialize;
  };

  # Default llama-swap grouping makes Clef and both Qwen profiles exclusive.
  services.llama-swap.settings.models.clef-27b = {
    name = "clef-27b";
    description = "Cloudflare Clef 27B Q4_K_M decision model; use /v1/systemone";
    cmd = lib.getExe runner;
    proxy = "http://127.0.0.1:${toString port}";
    # Model initialization must finish first: docs/incidents.md#taipan-clef-decision-startup.
    checkEndpoint = "/v1/models/${model}";
    useModelName = model;
    concurrencyLimit = 1;
    ttl = 0;
    unloadTimeout = 60;
    metadata = {
      model_type = "decision";
      context = 4096;
    };
    capabilities = {
      "in" = ["text" "image"];
      "out" = ["decision"];
      tools = false;
      context = 4096;
    };
  };
}
