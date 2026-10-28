# The Rust rewrite of Max, running beside the Haskell max as a separate
# stack: its own user, database, directories and units, all named maxx.
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
      # The Haskell max's key for cliproxy, read as maxx.
      "maxx/cliproxy-api-key" = {
        sopsFile = ../../secrets/hosts/tank-max.yaml;
        key = "llm-profiles-gemini-3.8-flash-api-key";
        owner = "maxx";
        restartUnits = ["maxx.service"];
      };
    };

  services.maxx = {
    enable = true;
    settings = {
      owners_file = secret "owners";
      llm = {
        default = {
          model = "cliproxy/gemini-3.8-flash-high";
          effort = "high";
        };
        # The Haskell max's classifier too: one slot, so the two queue.
        intent.model = "h610/qwen3.5-4b-q4_k_m";
        providers = {
          cliproxy = {
            base_url = cliproxy.baseUrl;
            protocol = "chat";
            api_key_file = secret "cliproxy-api-key";
            models."gemini-3.8-flash-high" = {
              context_window = cliproxy.gemini.context;
              max_output = cliproxy.gemini.models."gemini-3.8-flash-high".output;
            };
          };
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
    };
  };
}
