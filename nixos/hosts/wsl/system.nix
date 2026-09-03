{
  inputs,
  lib,
  pkgs,
  ...
}: let
  tailnetAddress = "100.64.0.14";
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

  qwen84kRunner = modelUnitRunner "run-qwen38-84k" "podman-qwen38.service";
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
          name = "Qwen3.8 27B NVFP4 84K MTP3";
          description = "Native NVFP4 weights and KV cache; 8K vision budget";
          cmd = lib.getExe qwen84kRunner;
          proxy = "http://127.0.0.1:8100";
          metadata = {
            model_type = "vlm";
            context = 84000;
          };
          capabilities = commonModel.capabilities // {context = 84000;};
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
    patches = (old.patches or []) ++ [./llama-swap-proxy-backend-timings.patch];
    vendorHash = "sha256-LS+PBnNbtSr3cibu8Nb6DEkko78EVO2l+1hxgsj5Iiw=";
  });
in {
  imports = [
    inputs.nixos-wsl.nixosModules.wsl
  ];

  wsl = {
    enable = true;
    defaultUser = "hank";
    useWindowsDriver = true;
    wslConf = {
      network.generateResolvConf = false;
      network.generateHosts = false;
    };
  };
  hardware.graphics.extraPackages = [
    (pkgs.runCommand "wsl-nvidia-symlink" {} ''
      mkdir -p $out/lib
      ln -s /usr/lib/wsl/lib/libnvidia-ml.so.1 $out/lib/libnvidia-ml.so
    '')
  ];
  programs.nix-ld.enable = true;
  environment.variables = {
    LD_LIBRARY_PATH = "/run/opengl-driver/lib:/usr/lib/wsl/lib";
  };

  # WSL-specific CDI/loopback constraints: docs/incidents.md#wsl-vllm-nvfp4.
  hardware.nvidia-container-toolkit = {
    enable = true;
    discovery-mode = "wsl";
    suppressNvidiaDriverAssertion = true;
    mount-nvidia-executables = false;
    mount-nvidia-docker-1-directories = false;
  };

  virtualisation.podman.enable = true;
  virtualisation.oci-containers.backend = "podman";
  # 24 GB tuning and the local image provenance: docs/incidents.md#wsl-ninfer-24g.
  virtualisation.oci-containers.containers.qwen38 = {
    image = "localhost/ninfer:qwen38-24g-550d0ac-1880c63";
    autoStart = false;

    environment = {
      HTTP_PROXY = "http://127.0.0.1:7897";
      HTTPS_PROXY = "http://127.0.0.1:7897";
      NO_PROXY = "127.0.0.1,localhost,100.64.0.14";
    };

    volumes = [
      "/var/lib/qwen38/ninfer-models:/models:ro"
      "/var/lib/qwen38/ninfer-logs:/logs"
    ];

    extraOptions = [
      "--device=nvidia.com/gpu=all"
      "--network=host"
      "--ipc=host"
    ];

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
      "84000"
      "--default-max-tokens"
      "32768"
      "--kv-capacity"
      "84000"
      "--max-concurrency"
      "1"
      "--prefill-chunk"
      "1024"
      "--kv-dtype"
      "nvfp4"
      "--device-state-slots"
      "0"
      "--host-state-slots"
      "2"
      "--host-kv-mib"
      "1024"
      "--max-private-continuations"
      "2"
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

  # Default 262K profile; routing details: docs/incidents.md#wsl-ninfer-model-gateway.
  virtualisation.oci-containers.containers.qwen38-long = {
    image = "localhost/ninfer:qwen38-24g-550d0ac-1880c63";
    autoStart = true;

    environment = {
      HTTP_PROXY = "http://127.0.0.1:7897";
      HTTPS_PROXY = "http://127.0.0.1:7897";
      NO_PROXY = "127.0.0.1,localhost,100.64.0.14";
    };

    volumes = [
      "/var/lib/qwen38/ninfer-models:/models:ro"
      "/var/lib/qwen38/ninfer-logs:/logs"
    ];

    extraOptions = [
      "--device=nvidia.com/gpu=all"
      "--network=host"
      "--ipc=host"
    ];

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
      "32768"
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
      "2"
      "--host-kv-mib"
      "1024"
      "--max-private-continuations"
      "2"
      "--max-shared-prefixes"
      "1"
      "--max-long-anchors-per-continuation"
      "1"
      "--media-cache-mib"
      "256"
      "--media-live-mib"
      "2048"
      "--vision-max-tokens"
      "4096"
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

  # Manual rollback profile; stop qwen38 before starting it because both own GPU 0 and port 8000.
  virtualisation.oci-containers.containers.qwen38-vllm = {
    image = "docker.io/vllm/vllm-openai:v0.28.0";
    autoStart = false;

    environment = {
      MAX_JOBS = "2";
      HTTP_PROXY = "http://127.0.0.1:7897";
      HTTPS_PROXY = "http://127.0.0.1:7897";
      NO_PROXY = "127.0.0.1,localhost,100.64.0.14";
    };

    volumes = [
      "/var/lib/qwen38/huggingface:/root/.cache/huggingface"
      "/var/lib/qwen38/vllm:/root/.cache/vllm"
    ];

    extraOptions = [
      "--device=nvidia.com/gpu=all"
      "--network=host"
      "--ipc=host"
    ];

    cmd = [
      "gittensor-model-hub/Qwen3.8-27B-NVFP4-RTX5090"
      "--served-model-name"
      "qwen3.8-27b"
      "--host"
      "100.64.0.14"
      "--port"
      "8000"
      "--quantization"
      "modelopt"
      "--kv-cache-dtype"
      "fp8"
      "--max-model-len"
      "100000"
      "--max-num-seqs"
      "1"
      "--max-num-batched-tokens"
      "2048"
      "--kv-cache-memory-bytes"
      "4300M"
      "--language-model-only"
      "--enable-prefix-caching"
      "--trust-remote-code"
      "--reasoning-parser"
      "qwen3"
      "--enable-auto-tool-choice"
      "--tool-call-parser"
      "qwen3_xml"
    ];
  };

  systemd.tmpfiles.rules = [
    "d /var/lib/qwen38/huggingface 0755 root root -"
    "d /var/lib/qwen38/vllm 0755 root root -"
    "d /var/lib/qwen38/ninfer-models 0755 root root -"
    "d /var/lib/qwen38/ninfer-logs 0755 root root -"
    "d /var/lib/qwen38/llama-swap-proxy 0750 llama-swap-proxy llama-swap-proxy -"
  ];

  systemd.services.podman-qwen38 = {
    after = ["network-online.target" "nvidia-container-toolkit-cdi-generator.service"];
    requires = ["nvidia-container-toolkit-cdi-generator.service"];
    conflicts = ["podman-qwen38-long.service" "podman-qwen38-vllm.service"];
  };
  systemd.services.podman-qwen38-long = {
    after = ["network-online.target" "nvidia-container-toolkit-cdi-generator.service"];
    requires = ["nvidia-container-toolkit-cdi-generator.service"];
    conflicts = ["podman-qwen38.service" "podman-qwen38-vllm.service"];
  };
  systemd.services.podman-qwen38-vllm = {
    after = ["network-online.target" "nvidia-container-toolkit-cdi-generator.service"];
    requires = ["nvidia-container-toolkit-cdi-generator.service"];
    conflicts = [
      "podman-qwen38.service"
      "podman-qwen38-long.service"
      "llama-swap.service"
      "llama-swap-proxy.service"
    ];
  };

  services.llama-swap = {
    enable = true;
    listenAddress = "127.0.0.1";
    port = llamaSwapPort;
    settings = llamaSwapSettings;
  };

  # llama-swap only starts/stops the declarative OCI units; NInfer remains
  # owned by NixOS rather than by an ad-hoc container command.
  systemd.services.llama-swap = {
    conflicts = ["podman-qwen38-vllm.service"];
    serviceConfig = {
      DynamicUser = lib.mkForce false;
      User = "root";
      Group = "root";
      PrivateUsers = lib.mkForce false;
      ProtectProc = lib.mkForce "default";
      ProcSubset = lib.mkForce "all";
    };
  };

  users.groups.llama-swap-proxy = {};
  users.users.llama-swap-proxy = {
    isSystemUser = true;
    group = "llama-swap-proxy";
  };

  systemd.services.llama-swap-proxy = {
    description = "Tailnet OpenAI gateway for llama-swap";
    wantedBy = ["multi-user.target"];
    wants = ["network-online.target" "tailscaled.service"];
    requires = ["llama-swap.service"];
    after = ["network-online.target" "tailscaled.service" "llama-swap.service"];
    conflicts = ["podman-qwen38-vllm.service"];

    serviceConfig = {
      Type = "simple";
      User = "llama-swap-proxy";
      Group = "llama-swap-proxy";
      ExecStart = lib.escapeShellArgs [
        (lib.getExe llamaSwapProxy)
        "--listen"
        "${tailnetAddress}:8000"
        "--upstream"
        "http://127.0.0.1:${toString llamaSwapPort}"
        "--config"
        llamaSwapConfig
        "--sessions-dir"
        "/var/lib/qwen38/llama-swap-proxy"
        "--default-user"
        "hank"
        "--opencode-hostname"
        "${tailnetAddress}:8000"
      ];
      Restart = "on-failure";
      RestartSec = 3;
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectHome = true;
      ProtectSystem = "strict";
      ReadWritePaths = ["/var/lib/qwen38/llama-swap-proxy"];
    };
  };

  networking.proxy.default = "http://127.0.0.1:7897";
  networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain,100.64.0.14";
  services.resolved = {
    enable = true;
    settings.Resolve.FallbackDNS = ["223.5.5.5"];
  };

  time.timeZone = "Asia/Hong_Kong";

  users.users.hank = {
    isNormalUser = true;
    extraGroups = ["wheel"]; # Enable ‘sudo’ for the user.
    packages = with pkgs; [
      tree
    ];
  };

  security.sudo.wheelNeedsPassword = false;
  programs.zsh.enable = true;
  programs.nix-index-database.comma.enable = true;

  # 没有 tsIp(不是部署目标),所以要显式开。见 nixos/modules/tailscale。
  my.tailscale.enable = true;

  services.openssh = {
    enable = true;
    ports = [2222];
  };
  # New-NetFirewallRule -DisplayName "WSL SSH" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 2222

  system.stateVersion = "25.11";
}
