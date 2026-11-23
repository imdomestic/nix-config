{
  placement,
  agyPlacement,
}: let
  cliproxy = import ./cliproxy-models.nix {inherit placement;};
  codex62 = import ./codex-6.2.nix;
  inherit (cliproxy) baseUrl;
  proxy = model: aliases: {
    provider = "cliproxy";
    protocol = "openai-chat";
    base_url = baseUrl;
    api_key_env = "CLIPROXY_API_KEY";
    inherit model aliases;
    timeout_seconds = 90;
    thinking = "auto";
    capabilities = {
      tools = true;
      streaming = true;
      json_mode = true;
      vision = true;
    };
  };
  # gaoji sizes the chat tail from the window (min(window / 8, 64k)) and assumes
  # 128k when none is given, which left a 16k tail; give it the real ones.
  gpt = model: aliases:
    (proxy model aliases)
    // {
      reasoning_effort = "low";
      max_input_tokens = cliproxy.gpt.input;
    };
  # GPT 6.2 through the Codex accounts: their input limits, not the public 1.05M.
  gpt62 = model: aliases:
    (proxy model aliases)
    // {
      reasoning_effort = "low";
      max_input_tokens = codex62.models.${model}.input;
    };
  gemini = model: aliases:
    (proxy model aliases)
    // {
      max_input_tokens = cliproxy.gemini.context;
      capabilities = (proxy model aliases).capabilities // {video = true;};
    };
  # Gemini 4 on the Antigravity subscription, through agy-proxy's Chat entry
  # (docs/agy-proxy.md). The model ID is the thinking preset, so no
  # reasoning_effort; gaoji carries agy's extra_content signatures back.
  # Argon thinks silently for up to ~110 s, hence the long timeout.
  gemini4 = family: level: context: aliases: {
    provider = "agy";
    protocol = "openai-chat";
    base_url = "https://${agyPlacement.tsName}/agy/v1";
    api_key_env = "AGY_API_KEY";
    model = "gemini-4-${family}-${level}";
    inherit aliases;
    timeout_seconds = 240;
    thinking = "auto";
    max_input_tokens = context;
    capabilities = {
      tools = true;
      streaming = true;
      json_mode = true;
      vision = true;
      video = true;
    };
  };
  hydrogen = cliproxy.antigravityHydrogen.context;
  gemini4Profiles = builtins.listToAttrs (map (entry: {
      name = "gemini-4-${entry.family}-${entry.level}";
      value = gemini4 entry.family entry.level entry.context entry.aliases;
    }) (
      map (level: {
        family = "hydrogen";
        inherit level;
        context = hydrogen;
        aliases = optional (level == "high") "hydrogen";
      }) ["medium" "high" "xhigh"]
      ++ builtins.concatMap (family:
        map (level: {
          inherit family level;
          context = 262144;
          aliases = optional (level == "high") family ++ optional (family == "argon" && level == "high") "gemini4";
        }) ["medium" "high"]) ["neon" "argon" "carbon"]
    ));
  optional = cond: value:
    if cond
    then [value]
    else [];
in {
  # This embedded default wins over AI_MODEL_DEFAULT_PROFILE in gaoji's catalog.
  default = "gemini-3.8-flash-high";
  profiles = {
    deepseek = {
      provider = "deepseek";
      protocol = "openai-chat";
      base_url = "https://api.deepseek.com";
      api_key_env = "DEEPSEEK_API_KEY";
      model = "deepseek-v4-flash";
      thinking = "disabled";
      aliases = ["ds" "flash"];
    };
    "deepseek-pro" = {
      provider = "deepseek";
      protocol = "openai-chat";
      base_url = "https://api.deepseek.com";
      api_key_env = "DEEPSEEK_API_KEY";
      model = "deepseek-v4-pro";
      thinking = "disabled";
      aliases = ["pro"];
    };
    "qwen-local" = {
      provider = "qwen";
      protocol = "openai-chat";
      base_url = "http://taipan.inner.imdomestic.com:8000/v1";
      api_key_required = false;
      model = "qwen3.8-27b";
      timeout_seconds = 45;
      thinking = "disabled";
      aliases = ["qwen" "qwen27b"];
      fallback_profiles = ["gpt-6-luna" "gpt-6.1-sol" "deepseek"];
      capabilities = {
        tools = true;
        forced_tool_choice = false;
        streaming = true;
        json_mode = true;
        model_listing = true;
        vision = false;
      };
    };
    "gpt-6.2-sol" = gpt62 "gpt-6.2-sol" ["gpt62" "sol62"];
    "gpt-6.2-astra" = gpt62 "gpt-6.2-astra" ["astra62"];
    "gpt-6.1-sol" = gpt "gpt-6.1-sol" ["default" "gpt" "sol" "gpt61" "gpt-5.4" "gpt54" "gpt-5.5" "gpt55"];
    "gpt-6.1-terra" = gpt "gpt-6.1-terra" ["terra"];
    "gpt-6-astra" = gpt "gpt-6-astra" ["astra"];
    "gpt-6-sol" = gpt "gpt-6-sol" ["gpt6"];
    "gpt-6-luna" = gpt "gpt-6-luna" ["luna" "mini" "spark" "gpt-5.4-mini" "gpt54mini" "gpt-5.3-codex-spark"];
    "gpt-5.6-sol" = gpt "gpt-5.6-sol" ["sol56"];
    "gpt-5.6-terra" = gpt "gpt-5.6-terra" ["terra56"];
    "gpt-5.6-luna" = gpt "gpt-5.6-luna" ["luna56"];
    "codex-auto-review" = proxy "codex-auto-review" ["review"];
    # Think before answering, as Max's default does; deeper thinking needs a longer timeout.
    "gemini-3.8-flash-high" =
      (gemini "gemini-3.8-flash-high" ["gemini"])
      // {
        reasoning_effort = "high";
        timeout_seconds = 180;
      };
    "gemini-3.5-flash-lite" = gemini "gemini-3.5-flash-lite" ["gemini-lite"];
    "gemini-3.1-flash-lite" = gemini "gemini-3.1-flash-lite" [];
    "gemini-3-flash" = gemini "gemini-3-flash" [];
    "claude-sonnet-4-6" = proxy "claude-sonnet-4-6" ["sonnet"];
    "claude-opus-4-6-thinking" = proxy "claude-opus-4-6-thinking" ["opus"];
    inherit
      (gemini4Profiles)
      "gemini-4-hydrogen-medium"
      "gemini-4-hydrogen-high"
      "gemini-4-hydrogen-xhigh"
      "gemini-4-neon-medium"
      "gemini-4-neon-high"
      "gemini-4-argon-medium"
      "gemini-4-argon-high"
      "gemini-4-carbon-medium"
      "gemini-4-carbon-high"
      ;
  };
}
