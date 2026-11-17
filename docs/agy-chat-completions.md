# agy-proxy 的 OpenAI Chat Completions 兼容入口

v0.3.0 在原生 Gemini 之外增加**显式转换**的 `/v1/chat/completions`。
它不声称 OpenAI 与 Gemini 语义完全相同，不复制 agy 的系统提示词，也不
声称能解决 Pi 默认提示词引起的泛化 429。协议与已知问题见
[agy-proxy](agy-proxy.md) 和
[Pi 的原生入口 429](incidents.md#pi-agy-native-prompt-429)。

gizmo 配置已开启生产兼容入口；Pi 配置新增 `agy-completions/*`，Max 配置
新增同名 provider。具体部署结果见文末。Pi 的现有 native Gemini provider、
Max 的默认模型和旧 CLIProxy 都不变。

## 开启方式与地址

CLI 显式加 `--openai-compat`，并同时配置现有的本机 Keychain / 独立 OAuth
文件与 client key。只启动 native relay、不读取本机凭据时不能开启它。
所有新入口仍要求代理 key，固定上游 origin，不允许从请求指定上游 URL。

NixOS 使用原生模块选项：

```nix
services.agy-proxy.openaiCompat = true;
```

默认 false。gizmo 的 host 模块仅在 true 时增加 HTTPS `/agy/v1/`；后端
仍只监听 loopback 8319，不额外开放防火墙、native API 或 OAuth 控制面。
需要按正常的 r6s 构建 → gizmo 部署流程激活后，以下地址才可使用：

| 用途 | 本地后端 | gizmo HTTPS（开启并部署后） |
| --- | --- | --- |
| Chat | `/v1/chat/completions` | `/agy/v1/chat/completions` |
| 模型列表 | `/v1/models` | `/agy/v1/models` |
| 单模型 | `/v1/models/<real-id>` | `/agy/v1/models/<real-id>` |

这是 **Chat Completions**，不实现旧文本 `/v1/completions`、Responses、
embeddings 或 OpenAI hosted tools。模型 ID 是 `gemini-4-hydrogen-high`
这样的 Google 真实 ID，不是带 UI provider 前缀的 `agy/gemini-…`。

开启后，普通 OpenAI SDK 的 base URL 填到 `/agy/v1`，例如：

```python
from pathlib import Path
from openai import OpenAI

client = OpenAI(
    base_url="https://gizmo.inner.imdomestic.com/agy/v1",
    api_key=(Path.home() / ".local/state/agy-proxy/client-key").read_text().strip(),
)
answer = client.chat.completions.create(
    model="gemini-4-hydrogen-high",
    messages=[{"role": "user", "content": "Reply briefly."}],
    reasoning_effort="high",
    max_completion_tokens=8192,
)
print(answer.choices[0].message.content)
```

示例依赖客户端自行安装 OpenAI SDK；服务本身只有 Go 标准库依赖。
认证支持 Bearer 或 X-Goog-Api-Key，两者冲突时拒绝，不接受 URL query key。

## 转换范围

- 起始 system / developer 文本按原顺序加入 `systemInstruction`，不改变
  身份、不省略规则、不插入 agy prompt。为避免把后期指令提前，明确拒绝
  mid-conversation system / developer，而不是悄悄重排。
- user / assistant 文字、function tools、tool_choice（auto / none /
  required / 指定函数）；function 参数 schema 用 `parametersJsonSchema`
  原样传递，保留 enum、union、约束与函数名，不清理或改名。
- 工具结果用 tool_call_id 匹配此前 pending 调用。只合并同一工具轮次中
  相邻的 tool messages，不改变收到的结果顺序；缺结果、重复/孤立 ID
  或中间插入其他消息会明确拒绝。
- 支持 image_url / video_url 的 base64 data URL，input_audio 的 mp3/wav。
  **不主动下载远程媒体 URL**，避免向内网、元数据地址或任意站点发请求。
  工具结果当前只支持文本；其媒体应作为下一条 user 消息。
- temperature、top_p、seed、stop、n、max_tokens / max_completion_tokens；
  两种输出上限冲突时报错。reasoning_effort 支持 minimal / low / medium /
  high / xhigh，对应 native thinkingLevel，仍应按真实预设选模型 ID。
- response_format 支持 text、json_object、非 strict 的 json_schema。
  不承诺 OpenAI strict schema 语义；strict:true、无法强制的
  parallel_tool_calls:false、远程 URL、旧 functions、logprobs、未支持的
  sampling 参数等返回 400，不静默吞掉。store 只接受 false。

响应包含 `chat.completion` 或 SSE `chat.completion.chunk`，保留每个
candidate 的 index。普通文本在 content，thought 文本在非标准但常见的
reasoning_content。usage 的 completion_tokens = candidatesTokenCount +
thoughtsTokenCount，另有 reasoning_tokens、cached_tokens 明细。

STOP 对应 stop（有工具时为 tool_calls），MAX_TOKENS 对应 length，已知
安全/内容终止对应 content_filter；未知终止原因不假装正常成功。

## 签名与工具历史：不能丢 opaque metadata

Gemini 的签名不属于标准 OpenAI schema，故返回以下扩展字段：

```json
{
  "extra_content": {
    "agy": {
      "model": "gemini-4-hydrogen-high",
      "parts": ["<完整原生 model parts，实际为 JSON objects>"]
    }
  }
}
```

字段附在 assistant message，并在每个 tool_call 上各附一份，兼容只保留
工具 opaque fields 的客户端。functionCall part 原有的 thoughtSignature
也暴露为 `extra_content.google.thought_signature`，但没有签名就不制造。

streaming 时文字和工具参数正常流出；直到该 candidate 的原生终止事件，
才发完整 replay metadata。终止 chunk 的工具条目只有 index 和 metadata，
不重发函数名/args/id，避免客户端把 arguments 拼接两遍。

下一轮优先使用完整 native parts，核对模型、visible text、函数名和参数
仍与当前 assistant message 一致，然后原样回放其顺序、未知字段、原生
call ID 和所有 signature carriers。跨模型或已修改的历史报 400；不猜测
签名对应关系、不使用 bypass placeholder、不用全局缓存猜原始请求。

**客户端必须保留这些字段和 JSON 数字精度。** OpenAI SDK 使用完整 message
model_dump 时通常能保留扩展；手写客户端只抽 content/tool_calls 标准字段
则不能指望 Gemini 工具历史仍有效。丢失两层 native replay metadata 且没有
原生 Google signature 时明确拒绝，不伪造一个签名让它继续。

## 错误、取消与资源边界

不重试 generation POST，不换账号或 credits，不把 429 解释成已证实的
风控。上游非 200 保留 HTTP status / Retry-After，原始 Google JSON 放在
OpenAI error.details 内；不暴露 cookies 或 redirect Location。

HTTP 200 内的 error、prompt block、非法 SSE、读写失败、缺少原生终止或
截断事件均结束失败。流已开启时尽量发安全 error SSE，随后中断连接；
**不补 STOP，不在失败之后发送 DONE**。只有验证正常终止与完整 EOF 后
才发 DONE。客户端取消会取消上游。

单请求默认 64 MiB，SSE 单事件与累计 replay 有界（包含每个工具上复制的
metadata），最多 32 candidates、65536 native parts、128 tools。输出媒体
或无法表达的 Gemini 输出变体明确失败，不静默丢掉。

## Max 与 Pi

Max 当前的 `protocol = "chat"` 可以使用这个入口，不再需要先给 Max 写
Gemini-native serializer；但仍须实际验证它的上下文和完整工具轮次。
当前 Max 的 Chat parser 已保留 message / tool_call 上的未知字段，因此
设计与它的 opaque replay 相容。Max provider 名为 `agy-completions`，使用
真实 Gemini IDs、这里的 base URL 和本服务的调用 key；不改变 default /
caption / dreamer / job，provider retries=0，避免把已知 429 自动多次重播。

代理 key 的 SOPS readers 是 Hank、gizmo 和 tank；Max 使用
`/run/secrets/maxx/agy-completions-api-key`。没有复用旧 CLIProxy key，
Google OAuth 不分发给 tank 或 VM。VM Pi 继续使用既有 Chat forwarder。
Pi 本机同时保留 native `agy/*` 与独立 `agy-completions/*`，后者共用相同
8 个实际型号和价格/预算，api 为 openai-completions，身份 scope 和稳定
session header 对这两个 provider 都生效，不影响 GPT 等其他 provider。
Max 的 Hydrogen 仍用既有的 256K 会话预算；新 provider 的视频能力暂不
标为已验收。

## 2026-11-17 · 实现验收

- `go test -race ./...`、`go vet ./...`、Nix 包构建通过。
- 离线覆盖：请求与 schema/参数约束、native parts/签名/大整数回放、
  流式 terminal metadata、usage、多 candidates、媒体限制、工具关联、
  错误/截断/取消、不重放 429、fixed-origin 认证边界及 opt-in 默认关闭。
- 本地运行真实转换逻辑，使用测试 transport 将其 native 请求送到 gizmo
  **已有 Gemini 入口**：JSON 文字、SSE 文字/usage/DONE、流式工具第一轮
  和携带 native signature 的第二轮均为 200 / 指定探针返回正确。
  测试不读取服务器 Google OAuth，只有现有代理调用 key；未变更生产路由。
- Nix 求值确认：默认 false 时没有 `/agy/v1/` location；显式打开后 unit
  含 `--openai-compat`，路由为 loopback `/v1/`。

可重复 opt-in live test（会调用账号模型，有额度消耗；默认单测不联网）：

```sh
AGY_CHAT_LIVE_URL=https://gizmo.inner.imdomestic.com/agy/v1beta \
AGY_CHAT_LIVE_KEY_FILE="$HOME/.local/state/agy-proxy/client-key" \
  go -C pkgs/agy-proxy test -run '^TestChatLiveThroughGemini$' -v -timeout 3m .
```

这些结果只证明已测转换和签名回放有效。没有通过删减 Pi 默认规则来测过，
也没有证明转换能消除已记录的 Pi prompt 429。
