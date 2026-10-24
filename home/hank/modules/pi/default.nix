{
  config,
  lib,
  pkgs,
  ...
}: let
  cliproxy = import ../../../../lib/cliproxy-models.nix {placement = config.my.fleet.placements.cliproxy;};
  pricing = import ./pricing.nix;
  ccExtensions = pkgs.callPackage ../../../../pkgs/pi-cc-extensions {};
  mathExtension = pkgs.callPackage ../../../../pkgs/pi-math {};
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
  imports = [../sops];

  sops.secrets."cliproxy/api_key".sopsFile = ../../../../secrets/clients/cliproxy.yaml;

  # pi 没有 Home Manager 模块；只合并声明的字段，保留运行时写入的设置。
  home.activation.piSettings = lib.hm.dag.entryAfter ["writeBoundary"] ''
    run ${pkgs.python3}/bin/python ${../../../../scripts/merge-json-settings.py} \
      ${lib.escapeShellArg "${config.home.homeDirectory}/.pi/agent/settings.json"} \
      ${lib.escapeShellArg (builtins.toJSON {
      showHardwareCursor = true;
      terminal.images = "kitty";
    })}
    run ${pkgs.python3}/bin/python ${../../../../scripts/merge-json-settings.py} \
      ${lib.escapeShellArg "${config.home.homeDirectory}/.pi/agent/pi-cc-extensions.json"} \
      ${lib.escapeShellArg (builtins.toJSON {
      enableEditorPrefix = false;
      enableCustomFooter = false;
    })}
  '';

  # Keep the local editor/footer; see docs/decisions.md#pi-cc-extensions.
  home.file.".pi/agent/extensions/pi-cc-extensions".source = "${ccExtensions}/extensions";
  # Absolute imports let Pi resolve dependencies beside each package in the store.
  home.file.".pi/agent/extensions/pi-math.ts".text = ''
    export { default } from "${mathExtension}/src/index.ts";
  '';
  home.file.".pi/agent/themes/cc-dark.json".source = "${ccExtensions}/themes/cc-dark.json";
  home.file.".pi/agent/themes/cc-light.json".source = "${ccExtensions}/themes/cc-light.json";
  home.file.".pi/agent/extensions/prompt-prefix.ts".source = ./prompt-prefix.ts;
  home.file.".pi/agent/extensions/statusline.ts".source = ./statusline.ts;

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
        name = "CLIProxy (tank)";
        inherit (cliproxy) baseUrl;
        api = "openai-responses";
        # `!` 前缀让 pi 每次请求时执行命令取 key，明文不进 store。
        apiKey = "!${pkgs.coreutils}/bin/cat ${config.sops.secrets."cliproxy/api_key".path}";
        models =
          map (id: {
            inherit id;
            reasoning = true;
            thinkingLevelMap = gptLevels id;
            input = ["text" "image"];
            contextWindow = cliproxy.gpt.context;
            maxTokens = cliproxy.gpt.output;
            cost = pricing.${id};
          })
          cliproxy.gpt.ids
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
          cliproxy.gemini.models;
      };
    };
  };
}
