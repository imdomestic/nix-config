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
  # tmux-agent-sidebar 的 OpenCode 桥:一个 JS 插件,把 opencode 的事件经
  # hook.sh 转发给侧边栏二进制。文件由包构建时从 src 拷进插件目录
  # (pkgs/tmux-agent-sidebar),不在 store 里的话上游的软链装法无从谈起。
  agentSidebar = pkgs.callPackage ../../../pkgs/tmux-agent-sidebar {};
  sidebarBridge = "file://${agentSidebar}/share/tmux-plugins/tmux-agent-sidebar/.opencode/plugins/tmux-agent-sidebar.js";
  runtimePlugins = [
    modelStatsPlugin
    "file://${notificator}/notificator.js"
    "@tarquinen/opencode-dcp@3.1.15"
    "opencode-supermemory@2.0.13"
    "@franlol/opencode-md-table-formatter@0.0.6"
    "@zenobius/opencode-skillful@1.2.5"
    sidebarBridge
  ];
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
  imports = [inputs.sops-nix.homeManagerModules.sops];

  # 与 .sops.yaml 的管理员收件人一致，运行时从用户的 SSH key 派生 age key。
  sops.age.sshKeyPaths = ["${config.home.homeDirectory}/.ssh/id_ed25519"];
  sops.secrets."cliproxy/api_key" = {
    sopsFile = ../../../secrets/clients/cliproxy.yaml;
  };

  programs.opencode = {
    enable = true;
    package = inputs.llm-agents.packages.${system}.opencode;

    settings = {
      model = "ninfer/qwen3.8-27b";
      plugin = runtimePlugins;
      instructions = ["${shellStrategy}/shell_strategy.md"];
      provider.cliproxy = {
        npm = "@ai-sdk/openai";
        name = "CLIProxy (h610)";
        options = {
          baseURL = "http://h610.inner.imdomestic.com:8317/v1";
          apiKey = "{file:${config.sops.secrets."cliproxy/api_key".path}}";
        };
        # h610 /v1/models 的对话模型；Responses API 保留推理与工具调用。
        models =
          lib.genAttrs [
            "gpt-6.1-sol"
            "gpt-6-astra"
            "gpt-6-sol"
            "gpt-6-luna"
            "gpt-5.6-sol"
            "gpt-5.6-terra"
            "gpt-5.6-luna"
            "gpt-5.5"
          ] (model: {
            name = model;
            reasoning = true;
            tool_call = true;
            limit = {
              context = 1050000;
              input = 922000;
              output = 128000;
            };
            modalities = {
              input = ["text" "image"];
              output = ["text"];
            };
          });
      };
      provider.ninfer = {
        npm = "@ai-sdk/openai-compatible";
        name = "NInfer";
        options.baseURL = "http://b650.inner.imdomestic.com:8000/v1";
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

    # OpenCode 1.14+ 的 server 和 TUI 是两个进程，插件需要两边都加载。
    tui = {
      theme = "evergarden-winter";
      plugin = [
        modelStatsPlugin
        "@tarquinen/opencode-dcp@3.1.15"
        sidebarBridge
      ];
    };
    themes = {
      "evergarden-winter".theme = evergardenWinter;
      "kanso-zen".theme = kansoZen;
    };
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
  # opencode-skillful 启动时会扫描 skills 目录,一个都不存在就每次打印
  # "No valid base paths found for skill discovery" 的 warn(见
  # docs/incidents.md#opencode-skillful-startup-warning)。空目录即可消除;
  # 以后要加 skill 内容就放进 home.file."opencode/skills/..."。
  home.activation.createOpenCodeSkillsDir = lib.hm.dag.entryAfter ["writeFile"] ''
    skills_dir=${lib.escapeShellArg "${config.xdg.configHome}/opencode/skills"}
    $DRY_RUN_CMD ${pkgs.coreutils}/bin/install -d -m 0755 "$skills_dir"
  '';
}
