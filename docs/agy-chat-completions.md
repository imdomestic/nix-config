# agy-proxy 的 OpenAI Chat Completions 兼容入口

v0.3.0 在原生 Gemini 之外增加**显式转换**的 `/v1/chat/completions`。
它不声称 OpenAI 与 Gemini 语义完全相同，不复制 agy 的系统提示词，也不
声称能解决 Pi 默认提示词引起的泛化 429。协议与已知问题见
[agy-proxy](agy-proxy.md) 和
[Pi 的原生入口 429](incidents.md#pi-agy-native-prompt-429)。

gizmo 配置已开启生产兼容入口；Pi 配置新增 `agy-completions/*`，Max 配置
新增同名 provider。具体部署结果见文末。Pi 的现有 native Gemini provider、
Max 的默认模型和旧 CLIProxy 都不变。

## 2026-11-18 · Max 加入 Argon / Carbon，并退役 Vertex

Max 的 `agy-completions` 在原 8 型号上增加六个真实预设，合计 14 个：

```text
agy-completions/gemini-4-argon-low
agy-completions/gemini-4-argon-medium
agy-completions/gemini-4-argon-high
agy-completions/gemini-4-carbon-low
agy-completions/gemini-4-carbon-medium
agy-completions/gemini-4-carbon-high
```

这六条来自账号实际目录，逐一使用对应 reasoning_effort 的短 Chat 请求
验证 HTTP 200 / 指定文本返回正确。Argon / Carbon 当前没有 XHigh，
不创建假别名，也不把四档 Hydrogen 的能力移植过来。Max /model 选真实
ID；若显式用 /effort，按对应 Low / Medium / High 设置，Max 尚没有
每模型默认 effort 机制，原有会话/全局 effort 不是实际预设切换的证据。

新六条沿用 Max 之前的 262144 会话预算与公开 API 价格估算，输出预算
65536，不将目录的 Carbon 262144 输出上限当作每次必须输出这么多。
视频能力未独立验收，暂不声明。Hank Pi 的两个 provider 仍各是原来
8 个型号，没有顺便扩充或改变默认；主聊天、intent、dreamer、caption、
job 默认也不变。

两个 CLIProxy namespace `vertex/*`、`vertex-c820/*` 一并退役：Max 四条
旧模型配置和 SillyTavern 的 fleet-vertex 快捷项移除。Max 会话选型与
VM 持久化 agent 配置也要检查，不只从下拉列表删掉名称。gizmo 的
CLIProxy preStart 会将 runtime `auths/vertex-*.json` 移出加载目录，放进
private `retired-vertex/retired.*` 归档；不会删除其他账号、撤销 GCP
service-account key 或修改历史用量/聊天。原目录中两份 Vertex 描述文件
对应公开目录的 48 个带前缀模型，部署后需验证两个前缀均为零。

回归检查：`bash scripts/check-max-agy.sh`，确保新增六档、无假 XHigh、
无两组 Vertex 路由、其他默认未变。历史事故条目和负向退休检查里的
字符串不是生效模型，不为“零搜索结果”篡改历史。

## 2026-11-18 · agy-completions 客户端接入与部署

配置提交 `b5cf3150`：Hank Pi 通过 `my.pi.providers.agy-completions` 新增 8 个
`agy-completions/gemini-…`，与原生 `agy` 并存，不恢复 CLIProxy Gemini；
Max 同名 provider 的 8 个 ID 已加载。SOPS 为 tank 增加代理 key 的解密权，
key 本身未轮换；Google OAuth 仍只存在 gizmo。

- gizmo 在 r6s 构建（max-jobs=1、cores=2），加载 v0.3.0 与 `/agy/v1/`。
  实际 HTTPS `/agy/v1/models` 带 key 200（账号当时目录 25 条 Gemini），
  无 key 401；旧 CLIProxy PID `3761129` 未改变。
- gizmo 未重启或整套切换，运行代仍 `kxnnv8p7…`，加载内核 6.18.57。
  完整最新声明设为启动默认：
  `/nix/store/rddv6laixmbw3fcz8h4ils2rsycdpb45-nixos-system-gizmo-26.05.20261113.f1e5c35`。
  本次 runtime drop-ins 为 `/run/systemd/system/agy-proxy.service.d/90-agy-proxy.conf`
  和 nginx 同名 drop-in，引用该声明产物。重启后由已设默认的新系统接管。
- tank 构建只产生配置/unit/manifest；新旧软件/内核闭包没有变化，
  etc 仅 Max / vm-check 的 config path 改变。先 test 激活，再设 boot 默认，
  当前运行与启动均为：
  `/nix/store/lwj1by13xbh5h3r68wdh0k5xxd16vvl7-nixos-system-tank-26.05.20261113.f1e5c35`。
  内核未重启，仍 6.18.60；Max 原二进制不变，重新加载配置后 PID `1705818`，
  QQ gateway resumed=true。
- 原有 8 台 VM、8 个 forwarder 的 PID 全部保持不变；每个 `/llm` 目录都
  出现 8 条新 provider 模型，job 默认仍 `cliproxy-responses/gpt-6.1-sol`。
- 从 VM 3 的真实 Max forwarder 请求 `agy-completions/gemini-4-hydrogen-high`：
  流式工具第一轮 HTTP 200（21.03 秒，usage/DONE 和 native signature 在），
  第二轮原样回放 HTTP 200（11.40 秒），返回指定 `MAX_AGY_COMPLETIONS_OK`。
  只执行固定结果 stub，没有给 VM 配真实 key，也没有改真实群聊的选型。
- Main chat / intent / dreamer / caption / job 默认均未改；新 provider
  retries=0。切换单个 Max 会话可用
  `/model agy-completions/gemini-4-hydrogen-high`，其他预设同样按真实 ID。
- 两边回退 timers 都已取消；tank 第一次保护验收过早读取 forwarder 的
  旧目录而触发回退，补上有界 readiness 后重新部署成功。不能把进程
  active 当作两秒刷新周期的目录已更新。

### Pi 兼容边界：仅加入声明，未激活

当前 Pi 1.5.2 的 `openai-completions` provider 不保留这个转换层返回的
`extra_content`，小型自定义提示词的真实 read-tool 测试第一轮后在第二轮
返回 400（缺少 signature metadata）。Max 的 opaque fields 则保留，以上
Max 转发回放测试已通过。**Pi 的新条目目前只是用户要求的声明，不应宣称
完整工具回放兼容**；本机未激活 home、未切默认。后续要给 Pi 增加明确的
签名 metadata 适配，不能放宽服务器检查或伪造签名来绕过。

原生 `agy/*` 配置不受影响；既有 Pi 默认 prompt 429 仍按单独问题处理。
提示词身份 scope/session header 已同时覆盖两 provider，但它们不等于
解决 metadata 丢失或证明 Max 长群聊上下文不会遇到 429。

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
当前 gizmo 已按 r6s 构建 → gizmo 部署流程启用，地址如下：

| 用途 | 本地后端 | gizmo HTTPS |
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
