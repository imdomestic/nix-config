{
  config,
  inputs,
  lib,
  pkgs,
  ...
}: let
  cliproxy = import ../../../../lib/cliproxy-models.nix {placement = config.my.fleet.placements.cliproxy;};
  codex62 = import ../../../../lib/codex-6.2.nix;
  pricing = import ./pricing.nix;
  free = {
    input = 0;
    output = 0;
    cacheRead = 0;
    cacheWrite = 0;
  };
  gptLevels = id: {
    off =
      if lib.elem id (["gpt-6.1-sol" "gpt-6-astra"] ++ codex62.ids)
      then null
      else "none";
    minimal = null;
    low = "low";
    medium = "medium";
    high = "high";
    xhigh = "xhigh";
    max =
      if id == "gpt-5.5"
      then null
      else "max";
  };
  gpt = limits: id: base: let
    chatAlias = base == "gpt-chat-latest";
  in
    {
      inherit id;
      reasoning = !chatAlias;
      input =
        if chatAlias
        then ["text"]
        else ["text" "image"];
      contextWindow = limits.context;
      maxTokens = limits.output;
      cost =
        if chatAlias
        then free
        else pricing.${base};
    }
    // lib.optionalAttrs (!chatAlias) {thinkingLevelMap = gptLevels base;}
    // lib.optionalAttrs chatAlias {name = "Rewind GPT Chat Latest · 费用未估算";};
  rewindModels = lib.mapAttrsToList (id: gpt (cliproxy.rewind.modelLimits.${id} or cliproxy.rewind) id) cliproxy.rewind.models;
in {
  imports = [../sops];

  home.packages = [inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.pi];

  sops.secrets."cliproxy/api_key".sopsFile = ../../../../secrets/clients/cliproxy.yaml;

  # Pi 没有原生 Home Manager 模块；模型元数据进 store，密钥只在请求时读取。
  home.file.".pi/agent/models.json".text = builtins.toJSON {
    providers = {
      ninfer = {
        name = "NInfer";
        baseUrl = "http://taipan.inner.imdomestic.com:8000/v1";
        api = "openai-completions";
        apiKey = "ninfer";
        compat = {
          supportsDeveloperRole = false;
          supportsReasoningEffort = false;
          thinkingFormat = "qwen-chat-template";
          chatTemplateKwargs.enable_thinking."$var" = "thinking.enabled";
        };
        models = map (model:
          model
          // {
            reasoning = true;
            thinkingLevelMap = {
              minimal = null;
              low = "low";
              medium = "medium";
              high = null;
              xhigh = "xhigh";
              max = null;
            };
            input = ["text" "image"];
            cost = free;
          }) [
          {
            id = "qwen3.8-27b";
            name = "Qwen3.8 27B · Groupwise INT · 262K · Vision 8K · MTP3";
            contextWindow = 262144;
            maxTokens = 131072;
          }
          {
            id = "qwen3.8-27b-fast";
            name = "Qwen3.8 27B · NVFP4 · 100K · Vision 8K · MTP3";
            contextWindow = 100000;
            maxTokens = 100000;
          }
          {
            id = "qwen3.8-27b-aligned";
            name = "qwen3.8-27b-aligned";
            contextWindow = 262144;
            maxTokens = 262144;
          }
        ];
      };
      cliproxy = {
        name = "CLIProxy (${config.my.fleet.placements.cliproxy.host})";
        inherit (cliproxy) baseUrl;
        api = "openai-responses";
        apiKey = "!${pkgs.coreutils}/bin/cat ${lib.escapeShellArg config.sops.secrets."cliproxy/api_key".path}";
        models =
          map (id: gpt cliproxy.gpt id id) cliproxy.gpt.ids
          ++ map (id: (gpt codex62.models.${id} id id) // {name = codex62.models.${id}.name;}) codex62.ids
          ++ rewindModels
          ++ lib.concatMap (prefix:
            map (model:
              model
              // {id = "${prefix}/${lib.removePrefix "rewind/" model.id}";}
              // lib.optionalAttrs (model ? name) {name = lib.replaceStrings ["Rewind "] ["Rewind${lib.removePrefix "rewind" prefix} "] model.name;})
            rewindModels)
          ["rewind2" "rewind3" "rewind4"]
          ++ lib.mapAttrsToList (id: model: {
            id = "opencode/${id}";
            inherit (model) name;
            api = "openai-completions";
            reasoning = true;
            thinkingLevelMap = lib.genAttrs ["off" "minimal" "low" "medium" "high" "xhigh" "max"] (level:
              if lib.elem level (model.efforts or ["high"])
              then level
              else null);
            input = ["text" "image"];
            contextWindow = model.context;
            maxTokens = model.output;
            cost = pricing."opencode/${id}";
            compat = {
              supportsReasoningEffort = model ? efforts;
              thinkingFormat = "openai";
              requiresReasoningContentOnAssistantMessages = true;
              sendSessionAffinityHeaders = true;
              sessionAffinityFormat = "openrouter";
            };
          })
          cliproxy.opencode.models;
      };
    };
  };
}
