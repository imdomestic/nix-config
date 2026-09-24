{
  config,
  lib,
  pkgs,
  ...
}: let
  # Configuration/storage migration: docs/incidents.md#max-unified-state
  settings = {
    "debug" = false;
    "admin" = {
      "port" = 7700;
      "host" = "127.0.0.1";
      "webhook_base_url" = "https://max.imdomestic.com:8443";
      "token" = config.sops.placeholder."max/admin-token";
    };
    "search" = {
      "tavily_api_key" = config.sops.placeholder."max/search-tavily-api-key";
      "max_results" = 5;
      "timeout_seconds" = 30;
    };
    "intent" = {
      "profile" = "qwen3.5-4b-q4_k_m";
    };
    "owners" = [2678068576];
    "llm" = {
      "default" = "gpt-5.6-luna";
      "profiles" = {
        "claude-opus-4-6" = {
          "protocol" = "anthropic";
          "api_key" = config.sops.placeholder."max/llm-profiles-claude-opus-4-6-api-key";
          "base_url" = "https://how88.top";
          "model" = "claude-opus-4-6";
          "temperature" = 1;
          "timeout_seconds" = 300;
        };
        "qwen3.5-4b-q4_k_m" = {
          "protocol" = "openai";
          "api_key" = "sk-xxx";
          "base_url" = "http://h610.inner.imdomestic.com:11435/v1";
          "multimodal" = false;
          "model" = "qwen3.5-4b-q4_k_m";
          "effort" = "xhigh";
        };
        "qwen3.8-27b" = {
          "protocol" = "openai";
          "api_key" = config.sops.placeholder."max/llm-profiles-qwen3.8-27b-api-key";
          "base_url" = "http://b650.inner.imdomestic.com:8000/v1";
          "multimodal" = true;
          "model" = "qwen3.8-27b";
          "max_input_tokens" = 262144;
          "effort" = "xhigh";
        };
        "gpt-5.6-terra" = {
          "protocol" = "responses";
          "api_key" = config.sops.placeholder."max/llm-profiles-gpt-5.6-terra-api-key";
          "base_url" = "http://h610.inner.imdomestic.com:8317/v1";
          "model" = "gpt-5.6-terra";
          "effort" = "high";
          "multimodal" = true;
        };
        "gpt-6-astra" = {
          "protocol" = "responses";
          "api_key" = config.sops.placeholder."max/llm-profiles-gpt-6-astra-api-key";
          "base_url" = "http://h610.inner.imdomestic.com:8317/v1";
          "model" = "gpt-6-astra";
          "effort" = "xhigh";
          "multimodal" = true;
        };
        "gpt-5.6-sol" = {
          "protocol" = "responses";
          "api_key" = config.sops.placeholder."max/llm-profiles-gpt-5.6-sol-api-key";
          "base_url" = "http://h610.inner.imdomestic.com:8317/v1";
          "model" = "gpt-5.6-sol";
          "effort" = "high";
          "multimodal" = true;
        };
        "gpt-5.6-luna" = {
          "protocol" = "responses";
          "api_key" = config.sops.placeholder."max/llm-profiles-gpt-5.6-luna-api-key";
          "base_url" = "http://h610.inner.imdomestic.com:8317/v1";
          "model" = "gpt-5.6-luna";
          "effort" = "xhigh";
          "multimodal" = true;
        };
        "gpt-5.6-luna-medium" = {
          "protocol" = "responses";
          "api_key" = config.sops.placeholder."max/llm-profiles-gpt-5.6-luna-medium-api-key";
          "base_url" = "http://h610.inner.imdomestic.com:8317/v1";
          "model" = "gpt-5.6-luna";
          "effort" = "medium";
          "multimodal" = true;
        };
        "deepseek-v4-flash-vision-exp" = {
          "api_key" = config.sops.placeholder."max/llm-profiles-deepseek-v4-flash-vision-exp-api-key";
          "base_url" = "https://api.deepseek.com/v1";
          "model" = "deepseek-v4-flash-vision-exp";
          "temperature" = 0.7;
          "timeout_seconds" = 300;
          "multimodal" = true;
        };
        "deepseek-pro" = {
          "api_key" = config.sops.placeholder."max/llm-profiles-deepseek-pro-api-key";
          "base_url" = "https://api.deepseek.com/v1";
          "model" = "deepseek-v4-pro";
          "temperature" = 0.3;
        };
        "grok-4.5" = {
          "api_key" = config.sops.placeholder."max/llm-profiles-grok-4.5-api-key";
          "base_url" = "https://gy.hetaosu.xyz/v1";
          "model" = "grok-4.5";
          "multimodal" = true;
        };
        "glm-5.2" = {
          "api_key" = config.sops.placeholder."max/llm-profiles-glm-5.2-api-key";
          "base_url" = "https://opencode.ai/zen/go/v1";
          "model" = "glm-5.2";
          "timeout_seconds" = 300;
        };
        "glm-5.1" = {
          "api_key" = config.sops.placeholder."max/llm-profiles-glm-5.1-api-key";
          "base_url" = "https://opencode.ai/zen/go/v1";
          "model" = "glm-5.1";
          "timeout_seconds" = 300;
        };
        "kimi-k2.7-code" = {
          "api_key" = config.sops.placeholder."max/llm-profiles-kimi-k2.7-code-api-key";
          "base_url" = "https://opencode.ai/zen/go/v1";
          "model" = "kimi-k2.7-code";
          "timeout_seconds" = 300;
          "multimodal" = true;
        };
        "kimi-k2.6" = {
          "api_key" = config.sops.placeholder."max/llm-profiles-kimi-k2.6-api-key";
          "base_url" = "https://opencode.ai/zen/go/v1";
          "model" = "kimi-k2.6";
          "timeout_seconds" = 300;
        };
        "kimi-k3" = {
          "api_key" = config.sops.placeholder."max/llm-profiles-kimi-k3-api-key";
          "base_url" = "https://opencode.ai/zen/go/v1";
          "model" = "kimi-k3";
          "timeout_seconds" = 300;
          "multimodal" = true;
        };
        "mimo-v2.5" = {
          "api_key" = config.sops.placeholder."max/llm-profiles-mimo-v2.5-api-key";
          "base_url" = "https://opencode.ai/zen/go/v1";
          "model" = "mimo-v2.5-free";
          "timeout_seconds" = 300;
        };
        "qwen3.6-plus" = {
          "api_key" = config.sops.placeholder."max/llm-profiles-qwen3.6-plus-api-key";
          "base_url" = "https://opencode.ai/zen/go/v1";
          "model" = "qwen3.6-plus";
          "timeout_seconds" = 300;
        };
        "minimax-m3" = {
          "api_key" = config.sops.placeholder."max/llm-profiles-minimax-m3-api-key";
          "base_url" = "https://opencode.ai/zen/go/v1";
          "model" = "minimax-m3";
          "timeout_seconds" = 300;
          "multimodal" = true;
        };
        "minimax-m2.7" = {
          "api_key" = config.sops.placeholder."max/llm-profiles-minimax-m2.7-api-key";
          "base_url" = "https://opencode.ai/zen/go/v1";
          "model" = "minimax-m2.7";
          "timeout_seconds" = 300;
        };
      };
    };
    "memory" = {
      "extract_profile" = "gpt-5.6-luna";
    };
    "stickers" = {
      "caption_profile" = "gpt-5.6-luna";
    };
    "embedding" = {
      "base_url" = "http://h610.inner.imdomestic.com:11434/v1";
      "api_key" = "ollama";
      "model" = "bge-m3";
      "timeout_seconds" = 60;
    };
    "matrix" = {
      "homeserver" = "https://matrix.imdomestic.com:8448";
      "user_id" = "@max:imdomestic.com";
      "room_id" = "!TGJOXkFLlfLlOYrtPr:imdomestic.com";
      "mirror_qq_group" = 650536599;
      "sync_timeout_ms" = 30000;
      "access_token" = config.sops.placeholder."max/matrix-access-token";
    };
    "server" = {
      "host" = "127.0.0.1";
      "port" = 18080;
      "access_token" = config.sops.placeholder."max/server-access-token";
    };
    "cliproxy" = {
      "base_url" = "http://h610.inner.imdomestic.com:8317";
      "management_key" = config.sops.placeholder."cliproxy/management_key";
    };
    "log_color" = "always";
  };
  secretNames = ["admin-token" "search-tavily-api-key" "llm-profiles-claude-opus-4-6-api-key" "llm-profiles-qwen3.8-27b-api-key" "llm-profiles-gpt-5.6-terra-api-key" "llm-profiles-gpt-6-astra-api-key" "llm-profiles-gpt-5.6-sol-api-key" "llm-profiles-gpt-5.6-luna-api-key" "llm-profiles-gpt-5.6-luna-medium-api-key" "llm-profiles-deepseek-v4-flash-vision-exp-api-key" "llm-profiles-deepseek-pro-api-key" "llm-profiles-grok-4.5-api-key" "llm-profiles-glm-5.2-api-key" "llm-profiles-glm-5.1-api-key" "llm-profiles-kimi-k2.7-code-api-key" "llm-profiles-kimi-k2.6-api-key" "llm-profiles-kimi-k3-api-key" "llm-profiles-mimo-v2.5-api-key" "llm-profiles-qwen3.6-plus-api-key" "llm-profiles-minimax-m3-api-key" "llm-profiles-minimax-m2.7-api-key" "matrix-access-token" "server-access-token"];
in {
  sops.secrets =
    lib.genAttrs (map (name: "max/${name}") secretNames) (name: {
      sopsFile = ../../../secrets/hosts/h610-max.yaml;
      key = lib.removePrefix "max/" name;
      restartUnits = lib.optional (name == "max/server-access-token") "max-napcat.service";
    })
    // {
      "max/ops-preauthkey" = {
        sopsFile = ../../../secrets/hosts/h610-ops.yaml;
        key = "preauthkey";
        mode = "0400";
        restartUnits = ["max-ops-tailscaled.service"];
      };
    };
  sops.templates."max-config.json" = {
    content = builtins.toJSON settings;
    owner = "max-service";
    mode = "0400";
    restartUnits = ["max.service"];
  };
  services.max = {
    enable = true;
    operations = {
      enable = true;
      allowedGroups = [611798505 650536599];
      loginServer = "https://tailscale.imdomestic.com:8443";
      authKeyFile = config.sops.secrets."max/ops-preauthkey".path;
    };
    configFile = config.sops.templates."max-config.json".path;
    napcat = {
      enable = true;
      qq = "2107570581";
      websocketPort = settings.server.port;
      accessTokenFile = config.sops.secrets."max/server-access-token".path;
    };
  };
  systemd.services.max = {
    after = lib.mkAfter ["tailscaled.service" "ollama.service"];
    wants = lib.mkAfter ["tailscaled.service" "ollama.service"];
  };
  # The host's Headscale loopback alias must use the veth gateway inside maxops.
  systemd.services.max-ops-tailscaled.serviceConfig.BindReadOnlyPaths = [
    "${pkgs.writeText "max-ops-hosts" "10.232.0.1 tailscale.imdomestic.com\n"}:/etc/hosts"
  ];
}
