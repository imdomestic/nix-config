{
  config,
  inputs,
  lib,
  ...
}: let
  bonsai = import ../../../lib/bonsai-models.nix;
  serverHost =
    if config.my.host.name == "ms7e56"
    then "127.0.0.1"
    else inputs.self.hosts.ms7e56.tsName;
in {
  sops.secrets."bonsai/api_key".sopsFile = ../../../secrets/clients/bonsai.yaml;
  programs.opencode.settings = {
    model = lib.mkForce "local-bonsai/bonsai-main";
    provider.local-bonsai = {
      npm = "@ai-sdk/openai-compatible";
      name = "Bonsai NInfer · ms7e56";
      options = {
        baseURL = "http://${serverHost}:${toString bonsai.port}/v1";
        apiKey = "{file:${config.sops.secrets."bonsai/api_key".path}}";
        timeout = 600000;
      };
      models = lib.mapAttrs (id: model:
        {
          inherit (model) name;
          reasoning = true;
          tool_call = true;
          temperature = true;
          limit = {inherit (bonsai) context output;};
          modalities = {input = ["text"]; output = ["text"];};
          options.reasoningEffort = model.reasoningEffort;
        }
        // lib.optionalAttrs (id == "bonsai-main") {
          variants = lib.genAttrs ["low" "medium" "high"] (effort: {reasoningEffort = effort;});
        }) bonsai.models;
    };
    agent.aggressive = {
      description = "使用本地 Hikari 模型进行研究与代码分析";
      mode = "primary";
      model = "local-bonsai/bonsai-hikari";
      reasoningEffort = "medium";
      temperature = 1.0;
      top_p = 0.95;
    };
  };
}
