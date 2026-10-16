# tank 上 CLIProxy 的对话模型，opencode 与 pi 共用这一份。
# 两边都走 Responses API，保留推理与工具调用。
{
  baseUrl = "http://tank.inner.imdomestic.com:8317/v1";
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
  gemini = {
    context = 1048576;
    models = {
      "gemini-pro-agent" = {
        name = "Gemini 3.1 Pro (High)";
        output = 65535;
      };
      "gemini-3.1-pro-low" = {
        name = "Gemini 3.1 Pro (Low)";
        output = 65535;
      };
      "gemini-3-flash" = {
        name = "Gemini 3 Flash";
        output = 65536;
      };
      "gemini-3.6-flash-high" = {
        name = "Gemini 3.6 Flash (High)";
        output = 65536;
      };
      "gemini-3.7-flash-high" = {
        name = "Gemini 3.7 Flash (High)";
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
