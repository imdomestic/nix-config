{
  config,
  lib,
  pkgs,
  ...
}: let
  placement = config.my.fleet.placements.lumiverse;
  domain = config.my.host.tsName;
  origin = "http://${domain}:${toString placement.port}";
  port = 7860;
  state = "/var/lib/lumiverse";
  image = "ghcr.io/prolix-oc/lumiverse@sha256:3c6c0a94e3cabbcda04dcab1de3962a11b90440ec22d003e1dc8cb92c00be8f6";
  # Must match the image's org.opencontainers.image.revision label.
  source = pkgs.fetchFromGitHub {
    owner = "prolix-oc";
    repo = "Lumiverse";
    rev = "45f8db563e1c314ed2aab227613b28eb5ea1084e";
    hash = "sha256-wV/AuB1FHyKHOOxPsP7mO0Q9zKhp7OrVkGdxDCBOKG4=";
  };
  patchedSource = pkgs.applyPatches {
    name = "lumiverse-1.2.5-model-policy";
    src = source;
    patches = [./model-policy.patch];
  };
  placements = config.my.fleet.placements;
  endpoint = service: "http://${service.tsName}:${toString service.port}/v1";
  connection = id: name: baseUrl: defaultModel: {
    inherit id name baseUrl defaultModel;
    provider = "custom";
  };
  manifest = pkgs.writeText "lumiverse-bootstrap.json" (builtins.toJSON {
    endpoint = "http://127.0.0.1:${toString port}";
    inherit origin;
    username = "linwhite";
    passwordFile = "/run/credentials/lumiverse-bootstrap.service/password";
    defaultConnection = "bonsai-hikari";
    connections = [
      (connection "bonsai-hikari" "Bonsai Hikari · seraph 本机" "http://127.0.0.1:8002/bonsai/v1" "bonsai-hikari")
      (connection "bonsai-main" "Bonsai 2 · seraph 本机" "http://127.0.0.1:8002/bonsai/v1" "bonsai-main")
      (connection "cliproxy" "CLIProxy · 对话模型" "http://127.0.0.1:8002/cliproxy/v1" "gemini-3.8-flash-high")
      (connection "qwen-swift" "Qwen3.8 27B Swift · taipan" (endpoint placements.qwen-ninfer) "qwen3.8-27b")
      (connection "qwen-aligned" "Qwen3.8 27B Aligned · taipan" (endpoint placements.qwen-ninfer) "qwen3.8-27b-aligned")
      (connection "small-qwen" "Qwen3.5 4B · h610" (endpoint placements.small-qwen) "qwen3.5-4b-q4_k_m")
      (connection "ollama" "Ollama · tank" (endpoint placements.ollama) "qwen3:8b")
    ];
  });
in {
  assertions = [
    {
      assertion = config.services.tailscale.enable && placement.host == config.my.host.name && pkgs.stdenv.hostPlatform.system == "x86_64-linux";
      message = "Lumiverse's pinned amd64 image must run on its registered Tailnet host.";
    }
    {
      assertion = config.services.sillytavern.enable;
      message = "Lumiverse uses the existing loopback-only model credential routes.";
    }
  ];

  users.groups.lumiverse.gid = 976;
  users.users.lumiverse = {
    isSystemUser = true;
    uid = 976;
    group = "lumiverse";
  };
  systemd.tmpfiles.rules = ["d ${state} 0700 lumiverse lumiverse -"];
  sops.secrets."lumiverse/password" = {};
  sops.templates."lumiverse-environment".content = ''
    OWNER_PASSWORD=${config.sops.placeholder."lumiverse/password"}
  '';

  virtualisation.oci-containers.containers.lumiverse = {
    inherit image;
    user = "976:976";
    environment = {
      NODE_ENV = "production";
      PORT = toString port;
      LUMIVERSE_HOST = "127.0.0.1";
      DATA_DIR = "/app/data";
      HOME = "/app/data/home";
      BUN_RUNTIME_TRANSPILER_CACHE_PATH = "/app/data/.bun-transpiler-cache";
      OWNER_USERNAME = "linwhite";
      AUTH_BASE_URL = origin;
      TRUST_ANY_ORIGIN = "false";
      TRUSTED_ORIGINS = "${origin},http://127.0.0.1:${toString port}";
      TRUSTED_PROXIES = "127.0.0.1/32,::1/128";
      LUMIVERSE_SMART_MONITOR = "false";
      LUMIVERSE_ST_MIGRATE = "false";
      LUMIVERSE_SMOL = "true";
      LUMIVERSE_EXCLUDED_MODEL_PREFIXES = "rewind/";
    };
    environmentFiles = [config.sops.templates."lumiverse-environment".path];
    volumes = [
      "${state}:/app/data:rw"
      "${patchedSource}/src/llm/registry.ts:/app/src/llm/registry.ts:ro"
      "${./model-policy.ts}:/app/src/llm/model-policy.ts:ro"
    ];
    extraOptions = [
      "--network=host"
      "--cap-drop=ALL"
      "--security-opt=no-new-privileges"
      "--read-only"
      "--tmpfs=/tmp:rw,nosuid,nodev,size=512m"
      "--memory=4g"
      "--cpus=4"
      "--pids-limit=512"
    ];
  };

  systemd.services.lumiverse-bootstrap = {
    description = "Seed independent Lumiverse model connections through its native API";
    wantedBy = ["multi-user.target"];
    requires = ["podman-lumiverse.service"];
    after = ["podman-lumiverse.service"];
    partOf = ["podman-lumiverse.service"];
    script = ''
      ${pkgs.curl}/bin/curl --silent --show-error --fail --output /dev/null \
        --retry 60 --retry-connrefused --retry-delay 2 --retry-max-time 120 \
        http://127.0.0.1:${toString port}/api/auth/get-session
      exec ${pkgs.python3}/bin/python3 ${./bootstrap.py} ${manifest}
    '';
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      TimeoutStartSec = 180;
      User = "lumiverse";
      Group = "lumiverse";
      LoadCredential = ["password:${config.sops.secrets."lumiverse/password".path}"];
      UMask = "0077";
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      PrivateTmp = true;
      PrivateDevices = true;
      IPAddressDeny = "any";
      IPAddressAllow = "localhost";
      RestrictAddressFamilies = ["AF_UNIX" "AF_INET" "AF_INET6"];
    };
  };

  services.nginx.virtualHosts.lumiverse = {
    serverName = domain;
    listen = [
      {
        addr = domain;
        inherit (placement) port;
      }
    ];
    locations."/" = {
      proxyPass = "http://127.0.0.1:${toString port}";
      proxyWebsockets = true;
      recommendedProxySettings = false;
      extraConfig = ''
        proxy_set_header Host $host:$server_port;
        proxy_set_header X-Forwarded-Host $host:$server_port;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        gzip off;
      '';
    };
  };
  my.tailscale = {
    bindServices = ["nginx"];
    guardedTCPServices.nginx = [placement.port];
  };
  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [placement.port];
}
