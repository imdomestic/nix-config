{
  config,
  pkgs,
  ...
}: let
  modelDirectory = "/var/lib/qwen35-sycl/models";
  modelName = "Qwen_Qwen3.5-4B-Q4_K_M.gguf";
  modelPath = "${modelDirectory}/${modelName}";
  listenAddress = config.my.host.tsIp;
  listenPort = 11435;
  endpoint = "http://${listenAddress}:${toString listenPort}";
  warmupRequest = builtins.toJSON {
    model = "qwen3.5-4b-q4_k_m";
    messages = [
      {
        role = "user";
        content = "Reply with READY.";
      }
    ];
    temperature = 0;
    max_tokens = 8;
    chat_template_kwargs.enable_thinking = false;
  };
in {
  virtualisation.oci-containers.backend = "docker";
  virtualisation.oci-containers.containers.qwen35-sycl = {
    image = "ghcr.io/ggml-org/llama.cpp@sha256:9b1c2d30d81bcf00861f5a0f106c53f91f0a1e9b4ae44c6b3e566bd893e7b3b5";
    autoStart = true;

    environment.ONEAPI_DEVICE_SELECTOR = "level_zero:0";

    volumes = [
      "${modelDirectory}:/models:ro"
    ];

    extraOptions = [
      "--device=/dev/dri/card0"
      "--device=/dev/dri/renderD128"
      "--network=host"
    ];

    cmd = [
      "--model"
      "/models/${modelName}"
      "--alias"
      "qwen3.5-4b-q4_k_m"
      "--ctx-size"
      "131072"
      "--n-gpu-layers"
      "all"
      "--device"
      "SYCL0"
      "--parallel"
      "1"
      "--flash-attn"
      "on"
      "--cache-type-k"
      "q4_0"
      "--cache-type-v"
      "q4_0"
      "--reasoning"
      "off"
      "--host"
      listenAddress
      "--port"
      (toString listenPort)
      "--no-webui"
      "--metrics"
    ];
  };

  systemd.tmpfiles.rules = [
    "d ${modelDirectory} 0755 root root -"
  ];

  systemd.services.docker-qwen35-sycl = {
    after = ["network-online.target" "tailscaled.service"];
    wants = ["network-online.target" "tailscaled.service"];
    unitConfig.ConditionPathExists = modelPath;
  };

  systemd.services.qwen35-sycl-warmup = {
    description = "Warm Qwen3.5 SYCL inference graphs";
    after = ["docker-qwen35-sycl.service"];
    requires = ["docker-qwen35-sycl.service"];
    wantedBy = ["multi-user.target"];
    path = [pkgs.coreutils pkgs.curl pkgs.gnugrep];
    script = ''
      for _ in $(seq 1 180); do
        if curl --fail --silent --max-time 2 ${endpoint}/health \
          | grep --quiet '"status":"ok"'; then
          break
        fi
        sleep 1
      done

      curl --fail --silent --show-error --max-time 300 \
        ${endpoint}/v1/chat/completions \
        --header 'Content-Type: application/json' \
        --data-binary '${warmupRequest}' \
        >/dev/null
    '';
    serviceConfig.Type = "oneshot";
  };
}
