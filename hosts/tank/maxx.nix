# The Rust rewrite of Max, as its own stack: its own user, database,
# directories and units, all named maxx. The Haskell max is gone from tank;
# its database and /var/lib/max stay for maxx's import.
# Design: docs/rust-rewrite.md on the max repo's maxx branch. It reaches QQ
# through Tencent's official bot API, as the bot maxx.
{
  config,
  lib,
  ...
}: let
  cliproxy = import ../../lib/cliproxy-models.nix {placement = config.my.fleet.placements.cliproxy;};
  # owners: `qq:<user_openid>` per line, from the private chat's endpoint.
  secretNames = ["qq-app-id" "qq-app-secret" "owners"];
  secret = name: config.sops.secrets."maxx/${name}".path;
in {
  sops.secrets =
    lib.genAttrs (map (name: "maxx/${name}") secretNames) (_: {
      sopsFile = ../../secrets/hosts/tank-max.yaml;
      owner = "maxx";
      restartUnits = ["maxx.service"];
    })
    // {
      # The key the Haskell max had for cliproxy, still under its name.
      "maxx/cliproxy-api-key" = {
        sopsFile = ../../secrets/hosts/tank-max.yaml;
        key = "llm-profiles-gemini-3.8-flash-api-key";
        owner = "maxx";
        restartUnits = ["maxx.service"];
      };
      # web_search's, Exa's: the Haskell max's, under its name.
      "maxx/exa-api-key" = {
        sopsFile = ../../secrets/hosts/tank-max.yaml;
        key = "search-exa-api-key";
        owner = "maxx";
        restartUnits = ["maxx.service"];
      };
    }
    # The other providers' keys the Haskell max had, under its profiles'
    # names; one profile's for a provider whose profiles share a key.
    // lib.mapAttrs' (name: profile:
      lib.nameValuePair "maxx/${name}-api-key" {
        sopsFile = ../../secrets/hosts/tank-max.yaml;
        key = "llm-profiles-${profile}-api-key";
        owner = "maxx";
        restartUnits = ["maxx.service"];
      }) {
      taipan = "qwen3.8-27b";
      deepseek = "deepseek-v4-flash-vision-exp";
    };

  services.maxx = {
    enable = true;
    # The groups' VMs, where the tools run: 32 at a time, 2 vCPUs and
    # 4 GiB each, on taps from 10.235.0.0/24.
    vm.enable = true;
    settings = {
      owners_file = secret "owners";
      llm = {
        default = {
          model = "cliproxy/gemini-3.8-flash-high";
          effort = "high";
        };
        # Summarizes the groups' history; without it nothing is summarized.
        historian = {
          model = "cliproxy/gemini-3.8-flash-high";
          effort = "high";
        };
        intent.model = "h610/qwen3.5-4b-q4_k_m";
        # Says what each new picture and sticker shows; the Haskell max's
        # captioner too.
        caption = {
          model = "cliproxy-responses/gpt-5.6-luna";
          effort = "low";
        };
        # The Haskell max's models that see pictures, for /model; maxx
        # takes every model to see them. A window nobody wrote down is the
        # Haskell max's default, 131072.
        providers = {
          cliproxy = {
            base_url = cliproxy.baseUrl;
            protocol = "chat";
            api_key_file = secret "cliproxy-api-key";
            models = {
              "gemini-3.8-flash-high" = {
                context_window = cliproxy.gemini.context;
                max_output = cliproxy.gemini.models."gemini-3.8-flash-high".output;
              };
              # Vertex AI, on the GCP trial's credit.
              "vertex/gemini-4-argon".context_window = 1048576;
            };
          };
          # The same cliproxy and key; GPT's reasoning only round-trips
          # through Responses.
          cliproxy-responses = {
            base_url = cliproxy.baseUrl;
            protocol = "responses";
            api_key_file = secret "cliproxy-api-key";
            models = lib.genAttrs ["gpt-6-astra" "gpt-5.6-sol" "gpt-5.6-terra" "gpt-5.6-luna"] (_: {
              context_window = cliproxy.gpt.context;
              max_output = cliproxy.gpt.output;
            });
          };
          taipan = {
            base_url = "http://taipan.inner.imdomestic.com:8000/v1";
            protocol = "chat";
            api_key_file = secret "taipan-api-key";
            models."qwen3.8-27b".context_window = 262144;
          };
          deepseek = {
            base_url = "https://api.deepseek.com/v1";
            protocol = "chat";
            api_key_file = secret "deepseek-api-key";
            models."deepseek-v4-flash-vision-exp".context_window = 131072;
          };
          # Not here, as of 2026-10-29: grok-4.5 (its relay answers 403
          # "Task APIs are private during staging deployment"), and
          # opencode's kimi-k3, kimi-k2.7-code and minimax-m3 (the key has
          # expired, and opencode now wants an x-opencode-session header).
          h610 = {
            base_url = "http://h610.inner.imdomestic.com:11435/v1";
            protocol = "chat";
            # llama.cpp's n_ctx.
            models."qwen3.5-4b-q4_k_m".context_window = 131072;
          };
        };
      };
      platforms.qq = {
        app_id_file = secret "qq-app-id";
        app_secret_file = secret "qq-app-secret";
      };
      search.api_key_file = secret "exa-api-key";
    };
  };
}
