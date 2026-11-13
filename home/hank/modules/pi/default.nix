{
  config,
  lib,
  pkgs,
  ...
}: let
  cliproxy = import ../../../../lib/cliproxy-models.nix {placement = config.my.fleet.placements.cliproxy;};
  balancePlacement = config.my.fleet.placements.rewind-balance;
  pricing = import ./pricing.nix;
  themes = import ./themes.nix;
  ccExtensions = pkgs.callPackage ../../../../pkgs/pi-cc-extensions {};
  betterRender = pkgs.callPackage ../../../../pkgs/pi-better-render {};
  subagents = pkgs.callPackage ../../../../pkgs/pi-tintin-subagents {};
  subagentsSettings = import ./subagents-settings.nix;
  extensionSource = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [./bootstrap.ts ./prompt-prefix.ts ./render.ts ./statusline.ts ./balance.ts ./subagents.ts];
  };
  free = {
    input = 0;
    output = 0;
    cacheRead = 0;
    cacheWrite = 0;
  };
  # NInfer 的 Qwen 只认这三档推理强度，其余档位在 pi 里隐藏。
  qwenLevels = {
    minimal = null;
    low = "low";
    medium = "medium";
    high = null;
    xhigh = "xhigh";
    max = null;
  };
  # 档位照 pi 内置 openai / google provider 里同名模型的 thinkingLevelMap。
  gptLevels = id: {
    off =
      if lib.elem id ["gpt-6.1-sol" "gpt-6-astra"]
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
  geminiLevels = id: {
    off = null;
    minimal =
      if lib.hasInfix "-pro" id
      then null
      else "minimal";
    low = "low";
    medium = "medium";
    high = "high";
    xhigh = null;
    max = null;
  };
in {
  imports = [
    ../sops
    ./options.nix
  ];

  sops.secrets."cliproxy/api_key".sopsFile = ../../../../secrets/clients/cliproxy.yaml;

  # pi 没有 Home Manager 模块；只合并声明的字段，保留运行时写入的设置。
  home.activation.piSettings = lib.hm.dag.entryAfter ["writeBoundary"] ''
    run ${pkgs.python3}/bin/python ${../../../../scripts/merge-json-settings.py} \
      ${lib.escapeShellArg "${config.home.homeDirectory}/.pi/agent/settings.json"} \
      ${lib.escapeShellArg (builtins.toJSON {
      showHardwareCursor = true;
      terminal.images = "kitty";
      compaction.enabled = true;
    })}
    run ${pkgs.python3}/bin/python ${../../../../scripts/merge-json-settings.py} \
      ${lib.escapeShellArg "${config.home.homeDirectory}/.pi/agent/mcp.json"} \
      ${lib.escapeShellArg (builtins.toJSON {
      mcpServers.exa = {
        url = "https://mcp.exa.ai/mcp?tools=web_search_exa,web_fetch_exa";
        enabled = true;
        exposure = "direct";
        description = "Search the web and fetch page contents with Exa.";
      };
    })}
    run ${pkgs.python3}/bin/python ${../../../../scripts/merge-json-settings.py} \
      ${lib.escapeShellArg "${config.home.homeDirectory}/.pi/agent/pi-cc-extensions.json"} \
      ${lib.escapeShellArg (builtins.toJSON {
      enableEditorPrefix = false;
      enableCustomFooter = false;
      enableMarkdownEnhance = false;
      # Keep the subagent plugin's live progress and workflow cards.
      excludeRenderers = ["Agent" "SubagentWorkflow" "get_subagent_result" "steer_subagent"];
    })}
    run ${pkgs.python3}/bin/python ${../../../../scripts/merge-json-settings.py} \
      ${lib.escapeShellArg "${config.home.homeDirectory}/.pi/agent/subagents.json"} \
      ${lib.escapeShellArg (builtins.toJSON subagentsSettings)}
  '';

  home.file.".pi/agent/extensions/hank-pi.ts".text = ''
    import bootstrap from "${extensionSource}/bootstrap.ts";
    import cc from "${ccExtensions}/extensions/index.ts";
    import better from "${betterRender}/src/index.ts";
    import subagents from "${subagents}/src/index.ts";

    export default function (pi) {
      bootstrap(pi, { cc, better, subagents }, ${builtins.toJSON {
      showTokenRate = false;
      balance = {
        url = "http://${balancePlacement.tsName}:${toString balancePlacement.port}/rewind/balance";
        apiKeyFile = config.sops.secrets."cliproxy/api_key".path;
      };
    }});
    }
  '';
  home.file.".pi/agent/themes/cc-dark.json".source = "${ccExtensions}/themes/cc-dark.json";
  home.file.".pi/agent/themes/cc-light.json".source = "${ccExtensions}/themes/cc-light.json";
  home.file.".pi/agent/themes/evergarden-fall.json".text = builtins.toJSON themes.evergarden-fall;
  home.file.".pi/agent/themes/evergarden-lunar.json".text = builtins.toJSON themes.evergarden-lunar;
  home.file.".pi/agent/themes/evergarden-spring.json".text = builtins.toJSON themes.evergarden-spring;
  home.file.".pi/agent/themes/evergarden-summer.json".text = builtins.toJSON themes.evergarden-summer;
  home.file.".pi/agent/themes/evergarden-winter.json".text = builtins.toJSON themes.evergarden-winter;
  home.file.".pi/agent/themes/kanso-ink.json".text = builtins.toJSON themes.kanso-ink;
  home.file.".pi/agent/themes/kanso-mist.json".text = builtins.toJSON themes.kanso-mist;
  home.file.".pi/agent/themes/kanso-pearl.json".text = builtins.toJSON themes.kanso-pearl;
  home.file.".pi/agent/themes/kanso-zen.json".text = builtins.toJSON themes.kanso-zen;
  home.file.".pi/agent/models.json".text = builtins.toJSON {
    providers =
      {
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
              thinkingLevelMap = qwenLevels;
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
          # `!` 前缀让 pi 每次请求时执行命令取 key，明文不进 store。
          apiKey = "!${pkgs.coreutils}/bin/cat ${config.sops.secrets."cliproxy/api_key".path}";
          models = let
            # Rewind 的已知型号跟随上游别名估价；动态 chat 别名不猜费用和推理能力。
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
          in
            map (id: gpt cliproxy.gpt id id) cliproxy.gpt.ids
            ++ rewindModels
            ++ map (model:
              model
              // {id = "rewind2/${lib.removePrefix "rewind/" model.id}";}
              // lib.optionalAttrs (model ? name) {name = lib.replaceStrings ["Rewind "] ["Rewind2 "] model.name;})
            rewindModels
            ++ lib.mapAttrsToList (id: model: {
              inherit id;
              inherit (model) name;
              reasoning = true;
              thinkingLevelMap = geminiLevels id;
              input = ["text" "image"];
              contextWindow = cliproxy.gemini.context;
              maxTokens = model.output;
              cost = pricing.${id};
            })
            cliproxy.gemini.models
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
                # CLIProxy expands this session into Go's x-opencode-session.
                sendSessionAffinityHeaders = true;
                sessionAffinityFormat = "openrouter";
              };
            })
            cliproxy.opencode.models;
        };
      }
      // (config.my.pi.providers or {});
  };
}
