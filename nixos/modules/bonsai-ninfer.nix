{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.bonsaiNinfer;
  bonsai = import ../../lib/bonsai-models.nix;
  runner = id: pkgs.writeShellApplication {
    name = "run-${id}";
    runtimeInputs = [pkgs.coreutils pkgs.systemd];
    text = ''
      # shellcheck disable=SC2329
      cleanup() {
        systemctl stop podman-${id}.service
      }
      trap cleanup EXIT INT TERM
      systemctl start podman-${id}.service
      while systemctl is-active --quiet podman-${id}.service; do
        sleep 1
      done
      exit 1
    '';
  };
  modelFilters = id: model: let
    locked = id == "bonsai-hikari";
    responseReasoning = {
      setParams."reasoning.effort" = model.reasoningEffort;
      setParamsIfAbsent = lib.optional (!locked) "reasoning.effort";
    };
  in {
    byPath = {
      "/v1/chat/completions" = {
        setParams = {
          reasoning_effort = model.reasoningEffort;
          temperature = 1.0;
          top_p = 0.95;
          top_k = 20;
          return_progress = true;
          timings_per_token = true;
        } // lib.optionalAttrs locked {
          enable_thinking = true;
          "chat_template_kwargs.enable_thinking" = true;
        };
        setParamsIfAbsent = ["temperature" "top_p" "top_k"]
          ++ lib.optional (!locked) "reasoning_effort";
      };
      "/v1/responses" = responseReasoning // {
        setParams = responseReasoning.setParams // {temperature = 1.0; top_p = 0.95;};
        setParamsIfAbsent = responseReasoning.setParamsIfAbsent ++ ["temperature" "top_p"];
      };
      "/v1/responses/input_tokens" = responseReasoning;
    };
  };
  settings = {
    # 加载实测约 5 秒；首次启动及磁盘读取预留 120 秒。
    healthCheckTimeout = 120;
    logLevel = "info";
    apiKeys = ["\${env.BONSAI_API_KEY}"];
    groups.bonsai = {
      members = lib.attrNames bonsai.models;
      swap = true;
      exclusive = true;
    };
    models = lib.mapAttrs (id: model: {
      inherit (model) name;
      cmd = lib.getExe (runner id);
      proxy = "http://127.0.0.1:${toString model.port}";
      useModelName = id;
      checkEndpoint = "/health";
      concurrencyLimit = 16;
      ttl = 0;
      unloadTimeout = 60;
      filters = modelFilters id model;
      metadata = {
        model_type = "llm";
        context = bonsai.context;
        max_context = bonsai.context;
        output = bonsai.output;
        capabilities = {tool_call = true; reasoning = true;};
      };
      capabilities = {
        "in" = ["text"];
        "out" = ["text"];
        tools = true;
        context = bonsai.context;
      };
    }) bonsai.models;
  };
in {
  options.services.bonsaiNinfer.enable = lib.mkEnableOption "Bonsai NInfer CUDA inference";

  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = config.my.host.name == "ms7e56";
      message = "Bonsai 的 SM120a 镜像与容量仅在 ms7e56 上验证。";
    }];
    sops.secrets."bonsai/api_key".sopsFile = ../../secrets/clients/bonsai.yaml;
    sops.templates."bonsai-environment".content = ''
      BONSAI_API_KEY=${config.sops.placeholder."bonsai/api_key"}
    '';
    hardware.nvidia-container-toolkit.enable = true;
    virtualisation.podman.enable = true;
    virtualisation.oci-containers = {
      backend = "podman";
      containers = lib.mapAttrs (id: model: {
        inherit (bonsai) image;
        autoStart = false;
        environment.NO_PROXY = "127.0.0.1,localhost,.inner.imdomestic.com";
        volumes = [
          "${bonsai.directory}/models:/models:ro"
          "${bonsai.directory}/service-logs:/logs:rw"
        ];
        extraOptions = ["--device=nvidia.com/gpu=all" "--network=host" "--ipc=host"];
        cmd = [
          "ninfer-serve" "/models/${model.file}"
          "--model-id" id "--host" "127.0.0.1" "--port" (toString model.port)
          "--max-context" (toString bonsai.context) "--kv-capacity" (toString bonsai.context)
          "--kv-dtype" "nvfp4" "--max-concurrency" "1"
          "--spec" "mtp" "--draft-tokens" (toString model.draftTokens)
          "--prefill-chunk" "1024" "--preserve-thinking"
          "--default-max-tokens" (toString bonsai.output)
          "--max-pending-requests" "16" "--pending-timeout-ms" "600000"
          "--request-log-jsonl" "/logs/${id}.jsonl"
        ];
      }) bonsai.models;
    };
    systemd.tmpfiles.rules = [
      "d ${bonsai.directory}/models 0755 root root -"
      "d ${bonsai.directory}/service-logs 0750 root root -"
    ];
    systemd.services = {
      bonsai-image-import = {
        description = "Import the pinned Bonsai NInfer OCI image";
        path = [pkgs.podman];
        script = ''
          if podman image exists ${lib.escapeShellArg bonsai.image}; then
            exit 0
          fi
          podman load --input ${lib.escapeShellArg "${bonsai.directory}/images/${bonsai.imageArchive}"}
          podman image exists ${lib.escapeShellArg bonsai.image}
        '';
        serviceConfig = {Type = "oneshot"; RemainAfterExit = true;};
      };
      llama-swap.serviceConfig = {
        DynamicUser = lib.mkForce false;
        User = "root";
        Group = "root";
        PrivateUsers = lib.mkForce false;
        ProtectProc = lib.mkForce "default";
        ProcSubset = lib.mkForce "all";
        EnvironmentFile = config.sops.templates."bonsai-environment".path;
        WorkingDirectory = lib.mkForce bonsai.directory;
      };
    } // lib.mapAttrs' (id: model: lib.nameValuePair "podman-${id}" {
      after = ["nvidia-container-toolkit-cdi-generator.service" "bonsai-image-import.service"];
      requires = ["nvidia-container-toolkit-cdi-generator.service" "bonsai-image-import.service"];
      conflicts = map (other: "podman-${other}.service") (lib.remove id (lib.attrNames bonsai.models));
      serviceConfig.ExecStartPre = [
        "${pkgs.coreutils}/bin/test -r ${bonsai.directory}/models/${model.file}"
      ];
    }) bonsai.models;
    services.llama-swap = {
      enable = true;
      package = pkgs.llama-swap.overrideAttrs (old: {
        patches = (old.patches or []) ++ [../../scripts/patches/llama-swap-parameter-defaults.patch];
      });
      listenAddress = "127.0.0.1";
      inherit (bonsai) port;
      inherit settings;
    };
  };
}
