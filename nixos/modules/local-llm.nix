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
        (toString bonsai.context)
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
        "256"
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
        "medium"
      ]
      ++ lib.optionals model.mtp ["--spec-type" "draft-mtp" "--spec-draft-n-max" "2"]);
  downloadModel = _id: model: ''
    target=${lib.escapeShellArg "${bonsai.directory}/${model.file}"}
    if [ ! -f "$target" ]; then
      curl --fail --location --show-error --continue-at - \
        --output "$target.partial" \
        ${lib.escapeShellArg "https://huggingface.co/${model.repository}/resolve/${model.revision}/${model.file}"}
      test "$(stat -c %s "$target.partial")" = ${toString model.bytes}
      printf '%s  %s\n' ${lib.escapeShellArg model.sha256} "$target.partial" | sha256sum --check --strict
      chmod 0644 "$target.partial"
      mv "$target.partial" "$target"
    fi
    test "$(stat -c %s "$target")" = ${toString model.bytes}
    printf '%s  %s\n' ${lib.escapeShellArg model.sha256} "$target" | sha256sum --check --strict
  '';
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
  systemd.services.bonsai-models = {
    description = "Download and verify the pinned Bonsai GGUF models";
    wants = ["network-online.target"];
    after = ["network-online.target" "systemd-tmpfiles-setup.service"];
    before = ["llama-swap.service"];
    path = [pkgs.curl pkgs.coreutils];
    environment.TMPDIR = "/var/lib/llm-models";
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      User = "llm-models";
      Group = "llm-models";
      StateDirectory = "llm-models";
      StateDirectoryMode = "0755";
      WorkingDirectory = bonsai.directory;
      TimeoutStartSec = "infinity";
      UMask = "0022";
    };
    script = lib.concatStringsSep "\n" (lib.mapAttrsToList downloadModel bonsai.models);
  };
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
