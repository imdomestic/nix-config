{
  config,
  inputs,
  lib,
  pkgs,
  ...
}: let
  system = pkgs.stdenv.hostPlatform.system;
  tuiPath = "${config.xdg.configHome}/opencode/tui.json";
  modelStats = pkgs.applyPatches {
    name = "opencode-model-stats-backend-timings";
    src = inputs.opencode-model-stats;
    patches = [./opencode-model-stats-backend-timings.patch];
  };
  modelStatsPlugin = [
    "file://${modelStats}"
    {
      prefillWsUrl = "ws://b650.inner.imdomestic.com:8000/prefill-ws";
    }
  ];
  notificator = pkgs.fetchFromGitHub {
    owner = "panta82";
    repo = "opencode-notificator";
    rev = "7b252f4c0a06b63d27c02f5ae074a8e8f61c5a5b";
    hash = "sha256-BzU4gtBcLw5RB5AL44+pTFQ+vl79FrzTpyV1cepLZ8U=";
  };
  shellStrategy = pkgs.fetchFromGitHub {
    owner = "JRedeker";
    repo = "opencode-shell-strategy";
    rev = "1303f24df1649202834e052f1d66560ed186e413";
    hash = "sha256-zv5wUMo/8ihyqdzFgLD+dQNandRGA33+NOokFwzsB+Y=";
  };
  runtimePlugins = [
    modelStatsPlugin
    "file://${notificator}/notificator.js"
    "@tarquinen/opencode-dcp@3.1.15"
    "opencode-supermemory@2.0.13"
    "@franlol/opencode-md-table-formatter@0.0.6"
    "@zenobius/opencode-skillful@1.2.5"
  ];
  both = color: {
    dark = color;
    light = color;
  };
  evergardenWinter = {
    primary = both "#cbe3b3";
    secondary = both "#b2caed";
    accent = both "#f7a182";
    error = both "#f57f82";
    warning = both "#f5d098";
    success = both "#cbe3b3";
    info = both "#b3e3ca";
    text = both "#f8f9e8";
    textMuted = both "#96b4aa";
    background = both "#1e2528";
    backgroundPanel = both "#191e21";
    backgroundElement = both "#262f33";
    border = both "#374145";
    borderActive = both "#4a585c";
    borderSubtle = both "#262f33";
    diffAdded = both "#cbe3b3";
    diffRemoved = both "#f57f82";
    diffContext = both "#96b4aa";
    diffHunkHeader = both "#6f8788";
    diffHighlightAdded = both "#4e5a4f";
    diffHighlightRemoved = both "#5a3e41";
    diffAddedBg = both "#36403b";
    diffRemovedBg = both "#3c3235";
    diffContextBg = both "#1e2528";
    diffLineNumber = both "#6f8788";
    diffAddedLineNumberBg = both "#4e5a4f";
    diffRemovedLineNumberBg = both "#5a3e41";
    markdownText = both "#f8f9e8";
    markdownHeading = both "#cbe3b3";
    markdownLink = both "#b2caed";
    markdownLinkText = both "#b3e6db";
    markdownCode = both "#dbe6af";
    markdownBlockQuote = both "#839e9a";
    markdownEmph = both "#f7a182";
    markdownStrong = both "#fae6ef";
    markdownHorizontalRule = both "#6f8788";
    markdownListItem = both "#f8f9e8";
    markdownListEnumeration = both "#b3e3ca";
    markdownImage = both "#b2caed";
    markdownImageText = both "#b3e6db";
    markdownCodeBlock = both "#dbe6af";
    syntaxComment = both "#839e9a";
    syntaxKeyword = both "#f57f82";
    syntaxFunction = both "#cbe3b3";
    syntaxVariable = both "#f8f9e8";
    syntaxString = both "#dbe6af";
    syntaxNumber = both "#f3c0e5";
    syntaxType = both "#f5d098";
    syntaxOperator = both "#96b4aa";
    syntaxPunctuation = both "#6f8788";
  };
in {
  programs.opencode = {
    enable = true;
    package = inputs.llm-agents.packages.${system}.opencode;

    settings = {
      model = "ninfer/qwen3.8-27b";
      plugin = runtimePlugins;
      instructions = ["${shellStrategy}/shell_strategy.md"];
      provider.ninfer = {
        npm = "@ai-sdk/openai-compatible";
        name = "NInfer";
        options.baseURL = "http://b650.inner.imdomestic.com:8000/v1";
        models = {
          "qwen3.8-27b-fast" = {
            name = "Qwen3.8 27B · NVFP4 · 100K · Vision 8K · MTP3";
            limit = {
              context = 100000;
              output = 100000;
            };
            modalities = {
              input = ["text" "image"];
              output = ["text"];
            };
          };
          "qwen3.8-27b" = {
            name = "Qwen3.8 27B · Groupwise INT · 262K · Vision 8K · MTP3";
            limit = {
              context = 262144;
              output = 262144;
            };
            modalities = {
              input = ["text" "image"];
              output = ["text"];
            };
          };
        };
      };
    };

    # OpenCode 1.14+ 的 server 和 TUI 是两个进程，插件需要两边都加载。
    tui = {
      theme = "evergarden-winter";
      plugin = [
        modelStatsPlugin
        "@tarquinen/opencode-dcp@3.1.15"
      ];
    };
    themes."evergarden-winter".theme = evergardenWinter;
  };

  # opencode-notificator invokes these programs directly on Linux.
  home.packages = lib.optionals pkgs.stdenv.isLinux [
    pkgs.ffmpeg
    pkgs.libnotify
  ];

  # OpenCode may persist TUI changes at runtime. Keep the schema/settings native,
  # then turn Home Manager's store symlink into a writable copy after activation.
  xdg.configFile."opencode/tui.json".force = true;
  home.activation.prepareMutableOpenCodeTui = lib.hm.dag.entryBefore ["linkGeneration"] ''
    tui_path=${lib.escapeShellArg tuiPath}
    if [[ -f "$tui_path" && ! -L "$tui_path" ]]; then
      $DRY_RUN_CMD ${pkgs.coreutils}/bin/rm -f "$tui_path"
    fi
  '';
  home.activation.materializeMutableOpenCodeTui = lib.hm.dag.entryAfter ["linkGeneration"] ''
    tui_path=${lib.escapeShellArg tuiPath}
    if [[ -L "$tui_path" ]]; then
      tui_source="$(${pkgs.coreutils}/bin/readlink -f "$tui_path")"
      $DRY_RUN_CMD ${pkgs.coreutils}/bin/install -m 0644 "$tui_source" "$tui_path.hm-new"
      $DRY_RUN_CMD ${pkgs.coreutils}/bin/mv -fT "$tui_path.hm-new" "$tui_path"
    fi
  '';
}
