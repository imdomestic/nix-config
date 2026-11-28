# fx(vercel-labs/fx)的模型对齐 pi(../pi):同一份 cliproxy / agy 模型表。
# fx 的 base_url 只收 https(http 只给 localhost),所以 cliproxy 走 gizmo 的
# HTTPS 入口,NInfer 走 taipan 的(hosts/taipan/ninfer-https.nix);agy 只有 OpenAI
# 兼容入口能用,而 fx 不回传 extra_content,带工具的第二轮会 400(docs/agy-proxy.md),
# 所以默认用 GPT。
{
  config,
  inputs,
  lib,
  pkgs,
  ...
}: let
  cliproxy = import ../../../../lib/cliproxy-models.nix {placement = config.my.fleet.placements.cliproxy;};
  codex62 = import ../../../../lib/codex-6.2.nix;
  gptLevels = import ../pi/gpt-levels.nix {inherit lib;};
  agyModels = import ../pi/agy-models.nix {inherit lib;};
  cliproxyHttps = "https://${config.my.fleet.placements.cliproxy.tsName}/v1";
  agyHttps = "https://${config.my.fleet.placements.agy-proxy.tsName}/agy/v1";
  ninferHttps = "https://${config.my.fleet.placements.qwen-ninfer.tsName}/v1";

  fx = inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.fx;
  # fx 的 key 只能来自环境变量;启动时从 sops 读,已设的不覆盖。
  fxWrapped = pkgs.writeShellScriptBin "fx" ''
    if [ -z "''${FX_CLIPROXY_API_KEY:-}" ] && [ -r ${lib.escapeShellArg config.sops.secrets."cliproxy/api_key".path} ]; then
      FX_CLIPROXY_API_KEY=$(< ${lib.escapeShellArg config.sops.secrets."cliproxy/api_key".path})
      export FX_CLIPROXY_API_KEY
    fi
    if [ -z "''${FX_AGY_API_KEY:-}" ] && [ -r ${lib.escapeShellArg config.sops.secrets."agy-proxy/api_key".path} ]; then
      FX_AGY_API_KEY=$(< ${lib.escapeShellArg config.sops.secrets."agy-proxy/api_key".path})
      export FX_AGY_API_KEY
    fi
    exec ${lib.getExe fx} "$@"
  '';

  # pi 的 thinkingLevelMap(档位名 → 发给上游的值,null 为不提供)转成 fx 的档位。
  efforts = field: levelMap:
    lib.mapAttrs (_: value: {${field} = value;})
    (lib.filterAttrs (_: value: value != null) levelMap);
  responsesEfforts = levelMap:
    efforts "reasoning" (lib.mapAttrs (_: value:
      if value == null
      then null
      else {effort = value;})
    levelMap);

  gpt = limits: base: let
    chatAlias = base == "gpt-chat-latest";
  in {
    context_window = limits.context;
    max_output_tokens = limits.output;
    supports_vision = !chatAlias;
    reasoning_efforts =
      if chatAlias
      then {}
      else responsesEfforts (gptLevels base);
  };
  rewindModels = lib.mapAttrs (id: gpt (cliproxy.rewind.modelLimits.${id} or cliproxy.rewind)) cliproxy.rewind.models;
in {
  imports = [../sops];

  sops.secrets."cliproxy/api_key".sopsFile = ../../../../secrets/clients/cliproxy.yaml;
  sops.secrets."agy-proxy/api_key".sopsFile = ../../../../secrets/clients/agy-proxy.yaml;

  home.packages = [fxWrapped];

  # fx 运行时自己写 settings.json(模型选择、权限等);只合并声明的字段,providers 整体替换。
  home.activation.fxSettings = lib.hm.dag.entryAfter ["writeBoundary"] ''
    run ${pkgs.python3}/bin/python ${../../../../scripts/merge-json-settings.py} \
      ${lib.escapeShellArg "${config.home.homeDirectory}/.fx/settings.json"} \
      ${lib.escapeShellArg (builtins.toJSON {
      auto_upgrade = false;
      providers = {
        cliproxy = {
          protocol = "openai-responses";
          base_url = cliproxyHttps;
          auth = {
            type = "bearer";
            env = "FX_CLIPROXY_API_KEY";
          };
          reviewer_model = "gpt-6-luna";
          title_model = "gpt-6-luna";
          model_metadata =
            lib.genAttrs cliproxy.gpt.ids (gpt cliproxy.gpt)
            // lib.genAttrs codex62.ids (id: gpt codex62.models.${id} id)
            // rewindModels
            // lib.concatMapAttrs (id: model:
              lib.listToAttrs (map (prefix: lib.nameValuePair "${prefix}/${lib.removePrefix "rewind/" id}" model)
                ["rewind2" "rewind3" "rewind4"]))
            rewindModels;
        };
        # OpenCode Go 经 CLIProxy 走 Chat Completions;fx 一个连接只有一种协议。
        cliproxy-chat = {
          protocol = "openai-chat-completions";
          base_url = cliproxyHttps;
          auth = {
            type = "bearer";
            env = "FX_CLIPROXY_API_KEY";
          };
          reviewer_model = "opencode/deepseek-v4.1-flash";
          title_model = "opencode/deepseek-v4.1-flash";
          model_metadata = lib.mapAttrs' (id: model:
            lib.nameValuePair "opencode/${id}" {
              context_window = model.context;
              max_output_tokens = model.output;
              supports_vision = lib.elem "image" model.modalities;
              # 不收 reasoning_effort 的模型只有固定的 high 一档。
              reasoning_efforts =
                if model ? efforts
                then lib.genAttrs model.efforts (level: {reasoning_effort = level;})
                else {high = {};};
            })
          cliproxy.opencode.models;
        };
        # 网关不验 key。模板只认 low / medium / xhigh(high 当 xhigh)。
        ninfer = {
          protocol = "openai-chat-completions";
          base_url = ninferHttps;
          auth.type = "none";
          reviewer_model = "qwen3.8-27b";
          title_model = "qwen3.8-27b";
          model_metadata = let
            qwen = context: output: {
              context_window = context;
              max_output_tokens = output;
              supports_vision = true;
              reasoning_efforts = {
                low.reasoning_effort = "low";
                medium.reasoning_effort = "medium";
                high.reasoning_effort = "xhigh";
              };
            };
          in {
            "qwen3.8-27b" = qwen 262144 131072;
            "qwen3.8-27b-aligned" = qwen 262144 262144;
          };
        };
        agy = {
          protocol = "openai-chat-completions";
          base_url = agyHttps;
          auth = {
            type = "bearer";
            env = "FX_AGY_API_KEY";
          };
          reviewer_model = "gemini-3.1-flash-lite";
          title_model = "gemini-3.1-flash-lite";
          model_metadata = lib.listToAttrs (map (model:
            lib.nameValuePair model.id {
              context_window = model.contextWindow;
              max_output_tokens = model.maxTokens;
              supports_vision = true;
              reasoning_efforts = efforts "reasoning_effort" model.thinkingLevelMap;
            })
          agyModels);
        };
      };
    })} \
      --replace providers \
      ${lib.escapeShellArg "--defaults=${builtins.toJSON {
      provider = "cliproxy";
      models.cliproxy = "gpt-6.2-sol";
      effort = "high";
    }}"}
  '';
}
