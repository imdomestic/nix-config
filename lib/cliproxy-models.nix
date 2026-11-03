# CLIProxy 的对话模型，opencode 与 pi 共用这一份。
# GPT 走 Responses；OpenCode Go 走 Chat Completions，保留推理与工具调用。
# 地址由 placements.cliproxy(flake/placements.nix)算出，max 和 h610 的
# gaoji profile 也从这里取。
{placement}: rec {
  origin = "http://${placement.tsName}:${toString placement.port}";
  baseUrl = "${origin}/v1";
  gpt = {
    context = 1050000;
    input = 922000;
    output = 128000;
    ids = [
      "gpt-6.1-sol"
      "gpt-6-astra"
      "gpt-6-sol"
      "gpt-6-luna"
      "gpt-5.6-sol"
      "gpt-5.6-terra"
      "gpt-5.6-luna"
      "gpt-5.5"
    ];
  };
  # Rewind 的显式前缀隔离 Codex；别名和客户端限额见 docs/rewind.md。
  rewind = {
    inherit (gpt) context input;
    output = 96000;
    models = {
      "rewind/gpt-5.6-luna" = "gpt-5.6-luna";
      "rewind/gpt-5.6-sol" = "gpt-5.6-sol";
      "rewind/gpt-5.6-terra" = "gpt-5.6-terra";
      "rewind/gpt-6-astra" = "gpt-6-astra";
      "rewind/gpt-6-luna" = "gpt-6-luna";
      "rewind/gpt-6-sol" = "gpt-6-sol";
      "rewind/gpt-6.1-sol" = "gpt-6.1-sol";
      "rewind/gpt-chat-latest" = "gpt-chat-latest";
    };
    # 未公布上限的动态别名用保守客户端预算，不代表上游能力。
    modelLimits."rewind/gpt-chat-latest" = {
      context = 128000;
      input = 111616;
      output = 16384;
    };
  };
  opencode = {
    baseUrl = "https://opencode.ai/inference/go/openai/v1";
    models = {
      "deepseek-v4.1-flash" = {
        name = "DeepSeek V4.1 Flash (OpenCode Go)";
        context = 1000000;
        output = 384000;
        modalities = ["text" "image"];
        efforts = ["low" "high" "max"];
      };
      "mimo-v2.6-flash" = {
        name = "MiMo V2.6 Flash (OpenCode Go)";
        context = 1048576;
        output = 131072;
        modalities = ["text" "image" "video" "audio"];
      };
    };
  };
  gemini = {
    context = 1048576;
    models = {
      "gemini-3-flash" = {
        name = "Gemini 3 Flash";
        output = 65536;
      };
      "gemini-3.8-flash-high" = {
        name = "Gemini 3.8 Flash (High)";
        output = 65536;
      };
      "gemini-3.1-flash-lite" = {
        name = "Gemini 3.1 Flash Lite";
        output = 65535;
      };
      "gemini-3.5-flash-lite" = {
        name = "Gemini 3.5 Flash Lite";
        output = 65535;
      };
    };
  };
}
