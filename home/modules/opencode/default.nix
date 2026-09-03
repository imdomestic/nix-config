{
  inputs,
  pkgs,
  ...
}: let
  system = pkgs.stdenv.hostPlatform.system;
  modelStats = pkgs.applyPatches {
    name = "opencode-model-stats-backend-timings";
    src = inputs.opencode-model-stats;
    patches = [./opencode-model-stats-backend-timings.patch];
  };
  modelStatsPlugin = [
    "file://${modelStats}"
    {
      prefillWsUrl = "ws://100.64.0.14:8000/prefill-ws";
    }
  ];
in {
  programs.opencode = {
    enable = true;
    package = inputs.llm-agents.packages.${system}.opencode;

    settings = {
      model = "ninfer/qwen3.8-27b";
      plugin = [modelStatsPlugin];
      provider.ninfer = {
        npm = "@ai-sdk/openai-compatible";
        name = "NInfer on 5090D v2";
        options.baseURL = "http://100.64.0.14:8000/v1";
        models = {
          "qwen3.8-27b-fast" = {
            name = "Qwen3.8 27B · NVFP4 · 84K · MTP3";
            limit = {
              context = 84000;
              output = 8192;
            };
            modalities = {
              input = ["text" "image"];
              output = ["text"];
            };
          };
          "qwen3.8-27b" = {
            name = "Qwen3.8 27B · Groupwise INT · 262K · MTP3";
            limit = {
              context = 262144;
              output = 8192;
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
    tui.plugin = [modelStatsPlugin];
  };
}
