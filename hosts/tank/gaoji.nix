{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.gaoji;
  runtimeDir = "/home/kenneth/services/gaoji";
  modelProfiles = import ../../lib/gaoji-model-profiles.nix {
    placement = config.my.fleet.placements.cliproxy;
  };
  modelEnvironment = pkgs.writeText "gaoji-models.env" ''
    # One model for every conversation keeps the provider cache warm; the
    # owner's /model changes it at runtime. No separate small-talk model.
    AI_MODEL_DEFAULT_PROFILE=gemini-3.8-flash-high
    AI_SIMPLE_CHAT_PROFILE=
    AI_REASONING_ROUTER_PROFILE=gemini-3.5-flash-lite
    AI_SYSTEM_PROMPT=
    AI_SYSTEM_PROMPT_FILE=
    # Sticker tagging and image descriptions; this file loads last, so it
    # overrides the older value in runtime.env.
    AI_VISION_PROFILE=gemini-3.8-flash-high
    AI_BACKGROUND_MODELS=gpt-6-astra,rewind/gpt-6-astra,rewind2/gpt-6-astra,rewind3/gpt-6-astra,rewind4/gpt-6-astra,rewind/gpt-6.1-sol,rewind2/gpt-6.1-sol,gpt-6.1-sol
    AI_BACKGROUND_CONTEXT_WINDOW=200000
    AI_MODEL_PROFILES_JSON='${builtins.toJSON modelProfiles}'
  '';
in {
  # Bot, QQ transport and NixOS container workspaces run together on tank.
  services.gaoji = {
    enable = true;
    qqOfficial = {
      enable = true;
      appIdFile = "${runtimeDir}/qq-official/app-id";
      appSecretFile = "${runtimeDir}/qq-official/app-secret";
      bindPepperFile = "${runtimeDir}/qq-official/bind-pepper";
      hostConfigFile = "${runtimeDir}/qq-official/host.json";
    };
    user = "kenneth";
    group = "users";
    stateDirectory = "qq-deepseek-bot";
    cacheDirectory = "qq-deepseek-bot";
    environmentFile = "${runtimeDir}/base.env";
    host = "100.64.0.4";
    port = 18080;
    admin = {
      secretFile = "${runtimeDir}/admin-key";
      origin = "https://gaoji.inner.imdomestic.com";
    };
    sandbox = {
      enable = true;
      workSnapshots.enable = true;
      backend = "container";
      vmRoot = "/data/services/gaoji/vms";
      # 自动运维 (2026-11-17): these conversations' containers reach the fleet with
      # `ssh <host>` as gaoji through the gaojiops tailnet node, like Max's
      # operations network. Owners are VM owner ids (sha256 of the QQ
      # endpoint key): the owner's private chat and one trusted group.
      # The node logs in once by hand (headscale register); no key here.
      operations = {
        enable = true;
        owners = [
          "qqo:conversation:050c72346da46b92c26c363d4f513d22cb895fe8e7c64925e43855c586a04797"
          "qqo:conversation:e5a1f0462ebd578c1b2dd78ece2d61152f679ab915b1ff11c52abfac89acb637"
        ];
        loginServer = "https://tailscale.imdomestic.com:8443";
        # tank's own tailnet IPv4: operations containers reach tank through gaojiops.
        hostAddress = "100.64.0.4";
        domain = "inner.imdomestic.com";
      };
    };
    voiceAsr.enable = true;
    runtimePackages = [pkgs.ffmpeg-headless];
    environment = {
      AI_OBSERVABILITY_ENABLED = "true";
      AI_METRICS_PATH = "/metrics";
      AI_SEMANTIC_ENABLED = "true";
      AI_EMBEDDING_BASE_URL = "http://h610.inner.imdomestic.com:11434/v1";
      AI_EMBEDDING_API_KEY = "ollama-local";
      AI_EMBEDDING_MODEL = "bge-m3";
      AI_EMBEDDING_DIMENSIONS = "1024";
      AI_EMBEDDING_TIMEOUT_SECONDS = "60";
      AI_GITHUB_LOGIN = "gaoji-ji";
      AI_GITHUB_USER_ID = "358294790";
      OTEL_SERVICE_NAME = "gaoji";
    };
  };

  sops.secrets."gaoji/bocha_api_key" = {
    owner = "kenneth";
    group = "users";
    mode = "0400";
    restartUnits = lib.optionals cfg.enable ["gaoji.service"];
  };

  sops.templates."gaoji-tank-postgres.env" = {
    owner = "kenneth";
    group = "users";
    mode = "0400";
    restartUnits = lib.optionals cfg.enable ["gaoji.service"];
    content = ''
      HOST=${cfg.host}
      PORT=${toString cfg.port}
      AI_POSTGRES_DSN=postgresql://qq_bot:${config.sops.placeholder."qq_bot/postgres_password"}@tank.inner.imdomestic.com:55432/qq_bot?target_session_attrs=read-write&connect_timeout=3&sslmode=require
      AI_POSTGRES_NODE_NAMES=tank
      AI_POSTGRES_POOL_MAX_SIZE=24
      AI_MEDIA_ROOT=/data/services/gaoji/media
      AI_ARCHIVE_ROOT=/data/services/kennethbot-archive
      AI_SANDBOX_MAX_TOTAL=12
      AI_SANDBOX_MAX_PER_USER=1
      AI_SANDBOX_MAX_FILE_MB=200
      AI_SEARCH_API_KEY=${config.sops.placeholder."gaoji/bocha_api_key"}
    '';
  };

  systemd.services.gaoji-interest = lib.mkIf (cfg.enable && cfg.runBot) {
    serviceConfig.InaccessiblePaths = ["-/data" "-/run/qq-bot-postgres-node" "-/run/secrets" "-/run/secrets-rendered"];
  };

  systemd.services.gaoji = lib.mkIf cfg.enable {
    after = ["tailscaled.service" "qq-bot-postgres-node.service"];
    wants = ["tailscaled.service" "qq-bot-postgres-node.service"];
    unitConfig.RequiresMountsFor = ["/data/services/gaoji" "/data/services/kennethbot-archive"];
    serviceConfig = {
      EnvironmentFile = lib.mkAfter [
        "${runtimeDir}/runtime.env"
        config.sops.templates."gaoji-tank-postgres.env".path
        "${runtimeDir}/qq-official/owner.env"
        modelEnvironment
      ];
      ReadWritePaths = ["/data/services/gaoji" "/data/services/kennethbot-archive"];
    };
  };

  my.monitoring.extraScrapeConfigs = lib.optionals cfg.enable [
    {
      job_name = "gaoji";
      metrics_path = "/metrics";
      scrape_interval = "15s";
      static_configs = [
        {
          targets = ["${cfg.host}:${toString cfg.port}"];
          labels.instance = config.my.host.name;
        }
      ];
    }
  ];
  # Keep a complete rule document in its own file; concatenated JSON documents
  # in services.prometheus.rules silently discard later groups.
  services.prometheus.ruleFiles = lib.optionals cfg.enable [
    (pkgs.writeText "gaoji-readiness.rules" (builtins.toJSON {
      groups = [
        {
          name = "gaoji-readiness";
          rules = import ../../system/modules/monitoring/gaoji-rules.nix;
        }
      ];
    }))
  ];

  # Pin the root-owned backup directory so the service cannot rename it via its writable parent.
  systemd.mounts = lib.optional (cfg.enable && cfg.sandbox.workSnapshots.enable) {
    what = "/data/services/gaoji/backups";
    where = "/data/services/gaoji/backups";
    type = "none";
    options = "bind";
    requiredBy = ["gaoji.service" "gaoji-work-snapshot.service"];
    before = ["gaoji.service" "gaoji-work-snapshot.service"];
  };

  systemd.tmpfiles.rules = lib.optionals cfg.enable [
    "d /data/services/gaoji 0750 kenneth users -"
    "d /data/services/gaoji/media 0750 kenneth users -"
    "r ${config.my.telemetry.textfileDir}/gaoji-qq.prom - - - -"
  ];
  networking.firewall.interfaces.tailscale0.allowedTCPPorts = lib.optionals cfg.enable [cfg.port];
}
