{lib, ...}: let
  bonsai = import ../../../lib/bonsai-models.nix;
in {
  programs.opencode.settings = {
    model = lib.mkForce "local-bonsai/bonsai-main";
    provider.local-bonsai = {
      npm = "@ai-sdk/openai-compatible";
      name = "Bonsai · ms7e56";
      options = {
        baseURL = "http://127.0.0.1:${toString bonsai.port}/v1";
        timeout = 600000;
      };
      models =
        lib.mapAttrs (_id: model: {
          inherit (model) name;
          reasoning = true;
          tool_call = true;
          temperature = true;
          limit = {
            context = bonsai.context;
            output = bonsai.output;
          };
          modalities = {
            input = ["text"];
            output = ["text"];
          };
          options.reasoningEffort = "medium";
        })
        bonsai.models;
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
