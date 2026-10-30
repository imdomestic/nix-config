{placement}: let
  baseUrl = (import ./cliproxy-models.nix {inherit placement;}).baseUrl;
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
  gpt = model: aliases: (proxy model aliases) // {reasoning_effort = "low";};
in {
  default = "gpt-6.1-sol";
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
    "gpt-6.1-sol" = gpt "gpt-6.1-sol" ["default" "gpt" "sol" "gpt61" "gpt-5.4" "gpt54" "gpt-5.5" "gpt55"];
    "gpt-6.1-terra" = gpt "gpt-6.1-terra" ["terra"];
    "gpt-6-astra" = gpt "gpt-6-astra" ["astra"];
    "gpt-6-sol" = gpt "gpt-6-sol" ["gpt6"];
    "gpt-6-luna" = gpt "gpt-6-luna" ["luna" "mini" "spark" "gpt-5.4-mini" "gpt54mini" "gpt-5.3-codex-spark"];
    "gpt-5.6-sol" = gpt "gpt-5.6-sol" ["sol56"];
    "gpt-5.6-terra" = gpt "gpt-5.6-terra" ["terra56"];
    "gpt-5.6-luna" = gpt "gpt-5.6-luna" ["luna56"];
    "codex-auto-review" = proxy "codex-auto-review" ["review"];
    "gemini-3.8-flash-high" = proxy "gemini-3.8-flash-high" ["gemini"];
    "gemini-3.5-flash-lite" = proxy "gemini-3.5-flash-lite" ["gemini-lite"];
    "gemini-3.1-flash-lite" = proxy "gemini-3.1-flash-lite" [];
    "gemini-3-flash" = proxy "gemini-3-flash" [];
    "claude-sonnet-4-6" = proxy "claude-sonnet-4-6" ["sonnet"];
    "claude-opus-4-6-thinking" = proxy "claude-opus-4-6-thinking" ["opus"];
  };
}
