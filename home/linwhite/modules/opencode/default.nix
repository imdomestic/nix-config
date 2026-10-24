{
  config,
  inputs,
  lib,
  pkgs,
  ...
}: let
  system = pkgs.stdenv.hostPlatform.system;
  latexPlugin = pkgs.callPackage ../../../../pkgs/opencode-latex {};
  cliproxy = import ../../../../lib/cliproxy-models.nix {placement = config.my.fleet.placements.cliproxy;};
  shellStrategy = pkgs.fetchFromGitHub {
    owner = "JRedeker";
    repo = "opencode-shell-strategy";
    rev = "1303f24df1649202834e052f1d66560ed186e413";
    hash = "sha256-zv5wUMo/8ihyqdzFgLD+dQNandRGA33+NOokFwzsB+Y=";
  };
  # 两套都只是暗色主题,dark / light 填同一个值。
  bothModes = lib.mapAttrs (_: color: {
    dark = color;
    light = color;
  });
  evergardenWinter = with (import ../palettes/evergarden-winter.nix).colors;
    bothModes {
      primary = green;
      secondary = blue;
      accent = orange;
      error = red;
      warning = yellow;
      success = green;
      info = aqua;
      inherit text;
      textMuted = subtext0;
      background = base;
      backgroundPanel = mantle;
      backgroundElement = surface0;
      border = surface1;
      borderActive = surface2;
      borderSubtle = surface0;
      diffAdded = green;
      diffRemoved = red;
      diffContext = subtext0;
      diffHunkHeader = overlay1;
      diffHighlightAdded = diffAddWord;
      diffHighlightRemoved = diffDelWord;
      diffAddedBg = diffAddBg;
      diffRemovedBg = diffDelBg;
      diffContextBg = base;
      diffLineNumber = overlay1;
      diffAddedLineNumberBg = diffAddWord;
      diffRemovedLineNumberBg = diffDelWord;
      markdownText = text;
      markdownHeading = green;
      markdownLink = blue;
      markdownLinkText = skye;
      markdownCode = lime;
      markdownBlockQuote = overlay2;
      markdownEmph = orange;
      markdownStrong = cherry;
      markdownHorizontalRule = overlay1;
      markdownListItem = text;
      markdownListEnumeration = aqua;
      markdownImage = blue;
      markdownImageText = skye;
      markdownCodeBlock = lime;
      syntaxComment = overlay2;
      syntaxKeyword = red;
      syntaxFunction = green;
      syntaxVariable = text;
      syntaxString = lime;
      syntaxNumber = pink;
      syntaxType = yellow;
      syntaxOperator = subtext0;
      syntaxPunctuation = overlay1;
    };
  # 按 kanso.nvim 的 extras/opencode/kanso-zen.json 逐项对应。
  kansoZen = with (import ../palettes/kanso-zen.nix).colors;
    bothModes {
      primary = blue3;
      secondary = violet2;
      accent = yellow3;
      error = red;
      warning = yellow;
      success = green;
      info = blue2;
      text = fg;
      textMuted = gray2;
      background = zenBg0;
      backgroundPanel = zenBg1;
      backgroundElement = zenBg2;
      border = zenBg1;
      borderActive = zenBg2;
      borderSubtle = zenBg1;
      diffAdded = gitGreen;
      diffRemoved = gitRed;
      # 上游这两项是 zenBg1,与 diffContextBg 同色,文字直接看不见。
      diffContext = gray2;
      diffHunkHeader = gray4;
      diffHighlightAdded = diffGreen;
      diffHighlightRemoved = diffRed;
      diffAddedBg = diffGreen;
      diffRemovedBg = diffRed;
      diffContextBg = zenBg1;
      diffLineNumber = gray2;
      diffAddedLineNumberBg = diffGreen;
      diffRemovedLineNumberBg = diffRed;
      markdownText = fg;
      markdownHeading = violet2;
      markdownLink = blue3;
      markdownLinkText = blue3;
      markdownCode = green3;
      markdownBlockQuote = gray2;
      markdownEmph = yellow3;
      markdownStrong = violet2;
      markdownHorizontalRule = gray2;
      markdownListItem = fg;
      markdownListEnumeration = gray2;
      markdownImage = blue3;
      markdownImageText = blue3;
      markdownCodeBlock = green3;
      syntaxComment = gray4;
      syntaxKeyword = violet2;
      syntaxFunction = blue3;
      syntaxVariable = fg;
      syntaxString = green3;
      syntaxNumber = pink;
      syntaxType = aqua;
      syntaxOperator = gray3;
      syntaxPunctuation = gray3;
    };
in {
  imports = [
    ../sops
    {
      options.my.opencode.prefillEndpoints = lib.mkOption {
        type = lib.types.listOf (lib.types.submodule {
          options = {
            url = lib.mkOption {type = lib.types.str;};
            apiKeyFile = lib.mkOption {type = lib.types.str;};
          };
        });
        default = [];
        description = "为后续 V2 插件迁移保留的模型进度 WebSocket。";
      };
    }
  ];

  sops.secrets."cliproxy/api_key" = {
    sopsFile = ../../../../secrets/clients/cliproxy.yaml;
  };

  programs.opencode = {
    enable = true;
    package = inputs.llm-agents.packages.${system}.opencode2;

    settings = {
      model = "ninfer/qwen3.8-27b";
      # 只启用已有 V2 入口的插件，见 docs/decisions.md#opencode-v2-migration。
      plugins = [
        "opencode-supermemory@2.0.17"
        "${latexPlugin}"
      ];
      instructions = ["${shellStrategy}/shell_strategy.md"];
      provider.cliproxy = {
        npm = "@ai-sdk/openai";
        name = "CLIProxy (tank)";
        options = {
          baseURL = cliproxy.baseUrl;
          apiKey = "{file:${config.sops.secrets."cliproxy/api_key".path}}";
        };
        models =
          lib.genAttrs cliproxy.gpt.ids (model: {
            name = model;
            reasoning = true;
            tool_call = true;
            limit = {inherit (cliproxy.gpt) context input output;};
            modalities = {
              input = ["text" "image"];
              output = ["text"];
            };
          })
          // lib.mapAttrs (_: model: {
            inherit (model) name;
            reasoning = true;
            tool_call = true;
            limit = {
              inherit (cliproxy.gemini) context;
              inherit (model) output;
            };
            modalities = {
              input = ["text" "image"];
              output = ["text"];
            };
          })
          cliproxy.gemini.models;
      };
      provider.ninfer = {
        npm = "@ai-sdk/openai-compatible";
        name = "NInfer";
        options.baseURL = "http://taipan.inner.imdomestic.com:8000/v1";
        models = {
          "qwen3.8-27b-aligned" = {
            name = "qwen3.8-27b-aligned";
            limit = {
              context = 262144;
              output = 262144;
            };
            modalities = {
              input = ["text" "image"];
              output = ["text"];
            };
          };
          "qwen3.8-27b" = {
            name = "qwen3.8-27b";
            limit = {
              context = 262144;
              output = 32768;
            };
            modalities = {
              input = ["text" "image"];
              output = ["text"];
            };
          };
        };
      };
    };

    # 当前 HM 只提供 tui；V2 首次启动将其与运行时偏好迁移到自管的 cli.json。
    tui = {
      theme = "evergarden-winter";
      plugin = [];
      keybinds.editor_open = "ctrl+g";
    };
    themes = {
      "evergarden-winter".theme = evergardenWinter;
      "kanso-zen".theme = kansoZen;
    };
  };

  # Homes last activated before 44c00a2f (2026-10-18) left a real tui.json, and
  # often a tui.json.backup, which makes Home Manager refuse to link over it.
  xdg.configFile."opencode/tui.json".force = true;
}
