# Pi 模型费用估算

核对日期：2026-10-18。配置在 `home/hank/modules/pi/pricing.nix`，单位均为
**美元 / 百万 token**，采用公开 API 的 Standard 付费价。
CLIProxy 的订阅额度和实际账单与这个估算金额并不等价。

| Pi 模型 ID | 输入 | 缓存读取 | 缓存写入 | 输出 |
| --- | ---: | ---: | ---: | ---: |
| gpt-6.1-sol | 2.00 | 0.10 | 2.50 | 10.00 |
| gpt-6-astra | 10.00 | 1.00 | 12.50 | 50.00 |
| gpt-6-sol | 2.00 | 0.20 | 2.50 | 10.00 |
| gpt-6-luna | 0.10 | 0.01 | 0.125 | 0.50 |
| gpt-5.6-sol | 4.00 | 0.40 | 5.00 | 20.00 |
| gpt-5.6-terra | 2.00 | 0.20 | 2.50 | 12.00 |
| gpt-5.6-luna | 0.20 | 0.02 | 0.25 | 1.20 |
| gpt-5.5 | 5.00 | 0.50 | 0 | 30.00 |
| gemini-3-flash | 0.50 | 0.05 | 0 | 3.00 |
| gemini-3.8-flash-high | 0.75 | 0.075 | 0 | 3.75 |
| gemini-3.1-flash-lite | 0.25 | 0.025 | 0 | 1.50 |
| gemini-3.5-flash-lite | 0.30 | 0.03 | 0 | 2.50 |

GPT 价格来源：[OpenAI 官方价目](https://developers.openai.com/api/docs/pricing)、
[GPT-6 Sol](https://developers.openai.com/api/docs/models/gpt-6-sol)、
[GPT-5.6 Sol](https://developers.openai.com/api/docs/models/gpt-5.6-sol)、
[Terra](https://developers.openai.com/api/docs/models/gpt-5.6-terra)、
[Luna](https://developers.openai.com/api/docs/models/gpt-5.6-luna)、
[GPT-5.5](https://developers.openai.com/api/docs/models/gpt-5.5)。
Gemini 价格来源：[Google 官方价目](https://ai.google.dev/gemini-api/docs/pricing)。

GPT 输入总量超过 272,000 token 时，输入、缓存读取和缓存写入单价乘 2，
输出乘 1.5。通过 Pi 原生 `cost.tiers` 配置；阈值包括输入、缓存读取和
缓存写入 token，按整个请求选择单价。Pi 按请求记录费用，不能追溯重算
GPT-5.5 官方描述的整段会话计费差异。

GPT-5.6 及之后模型的缓存写入是输入单价的 1.25 倍；GPT-5.5 没有额外
缓存写入费，首次输入通过普通输入计价，因此 `cacheWrite` 为 0。
见 [OpenAI Prompt caching](https://developers.openai.com/api/docs/guides/prompt-caching)。
Gemini 首次输入同样通过输入 token 计价；缓存存储的按小时费用不属于
Pi 的 token 费用字段。未额外估算搜索、工具、区域溢价或 Fast/Ultrafast 等费用。

CLIProxy 的 `gemini-3-flash` 按公开的 `gemini-3-flash-preview` 估价，
`gemini-3.8-flash-high` 按 `gemini-3.8-flash` 估价；这是对应公开型号的估算，
并非 Antigravity 订阅的计费规则。当前 Pi 模型仅声明文本和图片输入，
因此 Gemini 采用文本/图片价格。

Gemini 3.8 Flash 使用截至 **2026-12-31** 的引入价；Google 公布的
2027-01-01 起价格为输入 1.50、缓存读取 0.15、输出 7.50，届时应更新配置。
GPT-5.6 Sol 的当前优惠价至少持续到 **2026-11-21**，之后也应重新核对。

NInfer 的三个 Qwen 3.8 27B 变体为自托管推理，保持零 API token 费用，
不把硬件或电费换算为单价。Pi 会话文件已经记录的旧费用不会因修改
模型单价自动重算；重新加载模型后，后续响应按新单价计算。
