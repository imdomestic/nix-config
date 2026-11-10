{
  config,
  pkgs,
  ...
}: let
  bonsai = import ../../../../lib/bonsai-models.nix;
  serverHost = config.my.fleet.placements.bonsai-ninfer.tsName;
  free = {
    input = 0;
    output = 0;
    cacheRead = 0;
    cacheWrite = 0;
  };
in {
  sops.secrets."bonsai/api_key".sopsFile = ../../../../secrets/clients/bonsai.yaml;

  my.pi.providers.bonsai = {
    name = "Bonsai (${config.my.fleet.placements.bonsai-ninfer.host})";
    baseUrl = "http://${serverHost}:${toString bonsai.port}/v1";
    api = "openai-completions";
    apiKey = "!${pkgs.coreutils}/bin/cat ${config.sops.secrets."bonsai/api_key".path}";
    compat = {
      supportsDeveloperRole = false;
      supportsReasoningEffort = true;
      thinkingFormat = "openai";
    };
    models = [
      {
        id = "bonsai-main";
        name = bonsai.models.bonsai-main.name;
        reasoning = true;
        thinkingLevelMap = {
          off = "none";
          minimal = null;
          low = "low";
          medium = "medium";
          high = "high";
          xhigh = "xhigh";
          max = null;
        };
        input = ["text"];
        contextWindow = bonsai.context;
        maxTokens = bonsai.output;
        cost = free;
        samplingParams = {
          temperature = 1.0;
          top_p = 0.95;
        };
      }
      {
        id = "bonsai-hikari";
        name = bonsai.models.bonsai-hikari.name;
        reasoning = true;
        thinkingLevelMap = {
          off = null;
          minimal = null;
          low = null;
          medium = "medium";
          high = null;
          xhigh = null;
          max = null;
        };
        input = ["text"];
        contextWindow = bonsai.context;
        maxTokens = bonsai.output;
        cost = free;
        samplingParams = {
          temperature = 1.0;
          top_p = 0.95;
        };
      }
    ];
  };
}
