{
  lib,
  pkgs,
  ...
}: let
  bonsai = import ../../lib/bonsai-models.nix;
  engine = pkgs.callPackage ../../pkgs/llama-cpp-prism {};
  server = lib.getExe engine;
  modelCommand = id: model:
    lib.escapeShellArgs ([
        server
        "--model"
        "${bonsai.directory}/${model.file}"
        "--alias"
        id
        "--host"
        "127.0.0.1"
        "--port"
        "\${PORT}"
        "--ctx-size"
        (toString model.context)
        "--parallel"
        "1"
        "--n-gpu-layers"
        "999"
        "--flash-attn"
        "on"
        "--cache-type-k"
        "q8_0"
        "--cache-type-v"
        "q8_0"
        "--batch-size"
        "512"
        "--ubatch-size"
        "128"
        "--jinja"
        "--no-ui"
        "--temp"
        "1.0"
        "--top-p"
        "0.95"
        "--top-k"
        "20"
        "--min-p"
        "0.05"
        "--repeat-penalty"
        "1.0"
        "--n-predict"
        (toString bonsai.output)
        "--reasoning"
        "on"
        "--reasoning-effort"
        model.reasoningEffort
      ]
      ++ lib.optionals (id == "bonsai-main") ["--chat-template-file" (toString ./bonsai-main.jinja)]
      ++ lib.optionals model.mtp ["--spec-type" "draft-mtp" "--spec-draft-n-max" "2"]);
  modelManifest = pkgs.writeText "bonsai-models.json" (builtins.toJSON bonsai);
  modelService = force: {
    description =
      if force
      then "Fully verify the pinned Bonsai GGUF models"
      else "Prepare the pinned Bonsai GGUF models using verification stamps";
    after = ["systemd-tmpfiles-setup.service"];
    before = lib.optionals (!force) ["llama-swap.service"];
    path = [pkgs.curl];
    environment.TMPDIR = "/var/lib/llm-models";
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = !force;
      User = "llm-models";
      Group = "llm-models";
      StateDirectory = "llm-models";
      StateDirectoryMode = "0755";
      WorkingDirectory = bonsai.directory;
      TimeoutStartSec = "infinity";
      UMask = "0022";
    };
    script = ''
      exec ${lib.getExe pkgs.python3} ${../../scripts/bonsai-models.py} \
        --config ${modelManifest} ${lib.optionalString force "--force"}
    '';
  };
in {
  imports = [./bonsai-network.nix];
  users.groups.llm-models = {};
  users.users.llm-models = {
    isSystemUser = true;
    group = "llm-models";
    home = "/var/lib/llm-models";
  };
  systemd.tmpfiles.rules = [
    "d /var/lib/llm-models 0755 llm-models llm-models -"
    "d ${bonsai.directory} 0755 llm-models llm-models -"
  ];
  systemd.services.bonsai-models = modelService false;
  systemd.services.bonsai-models-verify = modelService true;
  services.llama-swap = {
    enable = true;
    listenAddress = "127.0.0.1";
    port = bonsai.port;
    openFirewall = false;
    settings = {
      healthCheckTimeout = 300;
      logLevel = "info";
      logToStdout = "both";
      startPort = 5800;
      models = lib.mapAttrs (id: model:
        {
          cmd = modelCommand id model;
          proxy = "http://127.0.0.1:\${PORT}";
        }
        // lib.optionalAttrs (id == "bonsai-hikari") {
          filters.setParams = {
            reasoning_effort = "medium";
            chat_template_kwargs = {
              enable_thinking = true;
              reasoning_effort = "medium";
            };
          };
        })
      bonsai.models;
    };
  };
  systemd.services.llama-swap = {
    requires = ["bonsai-models.service"];
    after = ["bonsai-models.service"];
    environment = {
      TMPDIR = "/run/llama-swap";
      CUDA_CACHE_PATH = "/var/cache/llama-swap";
    };
    serviceConfig = {
      SupplementaryGroups = ["video" "render"];
      WorkingDirectory = lib.mkForce bonsai.directory;
      RuntimeDirectory = "llama-swap";
      CacheDirectory = "llama-swap";
      PrivateTmp = lib.mkForce false;
      # CUDA 驱动需要执行生成代码，并使用真实设备权限。
      MemoryDenyWriteExecute = lib.mkForce false;
      PrivateUsers = lib.mkForce false;
    };
  };
}
