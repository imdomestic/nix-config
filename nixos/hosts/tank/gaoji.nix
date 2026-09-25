{config, lib, pkgs, ...}: let
  cfg = config.services.gaoji;
  runtimeDir = "/home/kenneth/services/gaoji";
in {
  # Staged for a single-active cutover. Never enable this while h610's bot is running.
  services.gaoji = {
    enable = false;
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
      botId = "3580515978";
    };
    cluster = {
      enable = true;
      localControlService = false;
      controlUrl = "http://h610.inner.imdomestic.com:8091";
      tokenFile = "${runtimeDir}/fleet-token";
      allowedGroups = [611798505 650536599];
    };
    sandbox = {
      enable = true;
      backend = "podman";
      vmImage = pkgs.fetchurl {
        url = "https://cloud.debian.org/images/cloud/trixie/20260525-2489/debian-13-genericcloud-amd64-20260525-2489.qcow2";
        hash = "sha256-YpoEI+UD4rkvuKVpHTMguTphOd7IYYkPhGCPp2tTixA=";
      };
      vmRoot = "/data/services/gaoji/vms";
    };
    sandbox.nixCacheVolume = "gaoji-tank-nix-v1";
    browser.enable = true;
    videoDeep = {
      enable = true;
      frameCount = 12;
      maxDownloadMB = 1024;
      maxDurationMinutes = 60;
      timeoutSeconds = 1800;
    };
    napcat.enable = false;
    runtimePackages = [pkgs.ffmpeg-headless];
    environment = {
      FORWARDED_ALLOW_IPS = "100.64.0.3";
      AI_OBSERVABILITY_ENABLED = "true";
      AI_METRICS_PATH = "/metrics";
      AI_PROMETHEUS_URL = "http://tank.inner.imdomestic.com:9009";
      AI_ALERTMANAGER_URL = "http://tank.inner.imdomestic.com:9093";
      AI_ALERT_NOTIFY_ENABLED = "false";
      AI_SEMANTIC_ENABLED = "true";
      AI_EMBEDDING_BASE_URL = "http://h610.inner.imdomestic.com:11434/v1";
      AI_EMBEDDING_API_KEY = "ollama-local";
      AI_EMBEDDING_MODEL = "bge-m3";
      AI_EMBEDDING_DIMENSIONS = "1024";
      AI_EMBEDDING_TIMEOUT_SECONDS = "60";
      OTEL_SERVICE_NAME = "gaoji";
    };
  };

  sops.templates."gaoji-tank-postgres.env" = {
    owner = "kenneth";
    group = "users";
    mode = "0400";
    restartUnits = lib.optionals cfg.enable ["gaoji.service"];
    content = ''
      HOST=${cfg.host}
      PORT=${toString cfg.port}
      AI_POSTGRES_DSN=postgresql://qq_bot:${config.sops.placeholder."qq_bot/postgres_password"}@tank.inner.imdomestic.com:55432,h610.inner.imdomestic.com:55432/qq_bot?target_session_attrs=read-write&connect_timeout=3&sslmode=require
      AI_POSTGRES_NODE_NAMES=tank,h610
      AI_MEDIA_ROOT=/data/services/gaoji/media
      AI_ARCHIVE_ROOT=/data/services/kennethbot-archive
      AI_SANDBOX_MAX_TOTAL=2
      AI_SANDBOX_MAX_PER_USER=1
    '';
  };

  systemd.services.gaoji = lib.mkIf cfg.enable {
    after = ["tailscaled.service" "qq-bot-postgres-node.service"];
    wants = ["tailscaled.service" "qq-bot-postgres-node.service"];
    unitConfig.RequiresMountsFor = ["/data/services/gaoji" "/data/services/kennethbot-archive"];
    serviceConfig = {
      EnvironmentFile = lib.mkAfter [
        "${runtimeDir}/runtime.env"
        config.sops.templates."gaoji-tank-postgres.env".path
      ];
      ReadWritePaths = ["/data/services/gaoji" "/data/services/kennethbot-archive"];
    };
  };

  systemd.tmpfiles.rules = lib.optionals cfg.enable [
    "d /data/services/gaoji 0750 kenneth users -"
    "d /data/services/gaoji/media 0750 kenneth users -"
  ];
  networking.firewall.interfaces.tailscale0.allowedTCPPorts = lib.optionals cfg.enable [cfg.port];
}
