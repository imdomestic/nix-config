# agy-proxy：Antigravity 订阅上的 Gemini / OpenAI 兼容网关

`pkgs/agy-proxy/` 是独立的 Go 程序，只用标准库，不复用 CLIProxy 的 translator / executor。
它是 Antigravity 订阅生成接口上的适配层，不是 Google Developer API、Vertex 或 OpenAI 全套服务
的镜像：只实现确实调用上游并返回真实结果的接口，不伪造 Files、缓存命中、batch、向量或后台 job。

gizmo 上的服务：模块 `system/modules/agy-proxy/default.nix`，主机配置 `hosts/gizmo/agy-proxy.nix`。
后端只监听 `127.0.0.1:8319`（独立 `agy-proxy` 用户，私有 state 目录，内存上限 512 MiB），
经 gizmo 已有的 Tailscale HTTPS 暴露，不开放其他端口，也不暴露 native / 控制面 / 登录接口：

| 协议 | base URL |
| --- | --- |
| Gemini | `https://gizmo.inner.imdomestic.com/agy/v1beta` |
| OpenAI 兼容（`services.agy-proxy.openaiCompat = true`，默认关，gizmo 开着） | `https://gizmo.inner.imdomestic.com/agy/v1` |

调用用代理自己的 key：`Authorization: Bearer <key>` 或 `X-Goog-Api-Key: <key>`，两者同时出现必须
相同；拒绝 URL 里的 `?key=`，也不会把客户端 key 转发给 Google。Google OAuth 只在 gizmo 上。

## 接口

| 方法 / 路径（相对各自 base URL） | 行为 |
| --- | --- |
| `GET /models`、`GET /models/<id>` | 按账号实时发现，只列 `gemini-*`；不支持分页 query |
| Gemini `POST /models/<id>:generateContent` | 原生 parts、工具、媒体、签名透传 |
| Gemini `POST /models/<id>:streamGenerateContent?alt=sse` | 原生流式生成，只解 `response` 外壳 |
| Gemini `POST /models/<id>:countTokens` | 上游真实计数，只计 contents |
| OpenAI `POST /chat/completions` | Chat 转换入口 |
| OpenAI `POST /responses` | 无状态 Responses，全历史输入加网关加密的 replay blob |
| OpenAI `POST /images/generations`、`/images/edits` | 用 Gemini 图像型号生成 / 编辑，返回 b64_json |
| OpenAI `POST /audio/transcriptions`、`/audio/translations` | 文件音频交给 Gemini 文本型号转写 / 译成英文 |
| `GET /capabilities` | 本网关的实现能力与限制说明，不是账号权限承诺 |
| `GET /healthz` | 只表示进程活着，不代表凭据或上游可用 |

模型一律用 discovery 返回的真实 ID（如 `gemini-4-hydrogen-high`），不接受 `gpt-image`、`whisper`
之类的别名，也不是 UI 里带 provider 前缀的 `agy/gemini-…`。账号目录会变（2026-11-18 起
Hydrogen 四档就不在列表里了），以实时目录为准。

## Gemini 入口

请求用 REST 的 camelCase 字段。网关只加 project、model、userAgent、requestType、requestId 外壳，
内层除了缺 `sessionId` 时补上，不改 JSON 语义：不替客户端选 thinkingLevel、不改 maxOutputTokens、
不加原生 prompt、不推测工具历史。JSON 可能被重新编码，所以这不是字节透传。

- `sessionId`：请求里有就用；否则用客户端的 `X-Agy-Session-Id`；都没有则每次新生成。
  多轮工具调用的客户端应发稳定的 session header，并原样回放返回的 model content 和签名，
  而不是只抽出 functionCall 丢掉签名。
- `X-Agy-Request-Id` 可显式携带请求 ID；缺省 ID 只模仿分段格式，不是 agy 的 trajectory，也不是幂等键。
- SSE 支持多行 data、event / id / retry、注释、未知字段和多 candidates。外层的 traceId /
  metadata 不出现在 Gemini 响应里，需要时用 native 入口。截断、读失败会断开连接，不补 STOP / DONE；
  客户端取消会取消上游。
- countTokens：只接受原生 `contents`（或只有 model / contents 的 generateContentRequest，
  model 须与 URL 一致），拒绝 tools、systemInstruction 等无法可靠计入的字段，返回上游
  totalTokens 并带 `X-Agy-Count-Scope: contents-only`。实测 `hello world` 无论带不带
  systemInstruction / tools 都是 2，所以不能拿它估算系统提示、工具 schema 或订阅费用。

## Chat Completions

转换是显式的，不声称 OpenAI 与 Gemini 语义相同，也不插入 agy 的系统提示词。

- 开头的 system / developer 按原顺序进 `systemInstruction`；对话中途的 system / developer 直接拒绝，
  不悄悄挪到前面。
- user / assistant 文本、function tools、`tool_choice`（auto / none / required / 指定函数）；
  参数 schema 用 `parametersJsonSchema` 原样传，enum、union、约束、函数名都不清理不改名。
- 工具结果按 `tool_call_id` 匹配之前的调用；只合并同一轮里相邻的 tool messages，顺序不变。
  缺结果、重复或孤立 ID、中间插了别的消息都拒绝。工具结果支持文本和 inline 图片（进
  `functionResponse.parts`）；音频 / 视频工具结果要用原生 Gemini。
- 媒体输入只接受 base64 data URL（image / video）和 `input_audio`（mp3 / wav）。**不下载远程 URL**，
  免得替请求方访问内网或任意站点。
- temperature、top_p、seed、stop、n、max_tokens / max_completion_tokens（两者冲突报错）；
  `reasoning_effort` 为 minimal / low / medium / high / xhigh，对应 native thinkingLevel，
  但换预设仍应换模型 ID。
- `response_format` 支持 text、json_object、非 strict 的 json_schema。strict:true、无法强制的
  `parallel_tool_calls:false`、远程 URL、旧 `functions`、logprobs、不支持的采样参数返回 400；
  `store` 只接受 false。旧 `/v1/completions`、embeddings、hosted tools 不在范围内。

响应是 `chat.completion` 或 SSE `chat.completion.chunk`，保留每个 candidate 的 index。thought 文本放在
`reasoning_content`；`completion_tokens` = candidatesTokenCount + thoughtsTokenCount，另有
reasoning_tokens、cached_tokens 明细。STOP → stop（有工具时 tool_calls），MAX_TOKENS → length，
已知安全终止 → content_filter；未知终止原因不当成功。

### 签名与工具历史

Gemini 的签名不在 OpenAI schema 里，所以响应带扩展字段，附在 assistant message 和每个
tool_call 上各一份：

```json
{"extra_content": {"agy": {"model": "gemini-4-hydrogen-high", "parts": ["<完整原生 model parts>"]}}}
```

functionCall part 上的 thoughtSignature 也放在 `extra_content.google.thought_signature`，没有就不造。
流式时文字和工具参数照常流出，到该 candidate 的原生终止事件才发完整 replay metadata；终止 chunk
里的工具条目只有 index 和 metadata，不重发 name / args / id，免得客户端拼两遍参数。

下一轮优先用完整 native parts：核对模型、可见文本、函数名和参数仍与 assistant message 一致后，
原样回放顺序、未知字段、原生 call ID 和全部签名。跨模型或被改过的历史报 400；两层 metadata 都丢了、
又没有原生签名时直接拒绝。不猜签名对应关系、不用 bypass placeholder、不用全局缓存猜原请求。
**客户端必须保留这些字段和 JSON 数字精度**：OpenAI SDK 用完整 message `model_dump` 通常能保留；
只抽 content / tool_calls 的手写客户端不行。

## Responses

无状态：只实现全历史重放的文本 / 多模态输入和函数工具子集，生成后端与 Chat 相同。
原生 model parts（含签名及其位置）保存在网关自己的 AES-GCM `encrypted_content` 里，密钥由代理 key
按用途派生，随机 nonce。它不是 OpenAI 的 blob，也不解密 Google 的隐藏思考。

- 要回放就发 `include: ["reasoning.encrypted_content"]`，下一轮传回完整 output items；网关核对原生
  模型、函数名、args 和可见内容一致后恢复 parts。代理 key 轮换会让旧 blob 失效，换 Google 账号后
  旧签名也不保证能用，应开新会话。
- `store:true`、`previous_response_id`、output item 引用、hosted tools、WebSocket、检索 / 删除 /
  取消已存储 response 都报错。
- SSE 只在真实完成时结束成功；缺原生终止或中途失败不补 completed / DONE。
  思考摘要是上游返回的可见文本，不是完整推理。

## 图片与音频

- 图片生成 / 编辑：`model` 必须是 `gemini-…-image…` 型号，走 image_gen lane。generations 只支持
  n=1，size 只接受映射好的正方形 1K / 2K / 4K 或单独的 aspect_ratio，返回 b64_json，不提供公网 URL。
  edits 用 multipart `image` / `image[]` + prompt，最多 4 张 PNG / JPEG / WebP；mask 等未知约束报错
  而不是忽略。上游没返回图片、拒绝、截断或媒体非法都报错，不把文字当图片。
- 音频：multipart `file`，必须指定 Gemini 文本型号。接受扩展名、Content-Type、容器签名一致的
  WAV / MP3 / M4A / MP4 / OGG / WebM / FLAC。`language` 是两字母提示，`prompt` 是词汇提示；
  `response_format` 只有 json `{text}` 或 text，没有时间戳、SRT / VTT、说话人分离。
  translations 的目标语言是英文。
- 没有 `/videos`、`/audio/speech`、实时音视频：订阅目录里没有可验证的后端。

## 限制与错误

- 请求体默认 64 MiB（`max-body-bytes`）；multipart 每文件 20 MiB、总计 32 MiB，在内存里有界处理，
  不落盘。SSE 单事件和累计 replay 有界；最多 32 candidates、65536 native parts、128 tools。
- 等上游响应头默认 120 秒（NixOS `upstreamHeaderTimeoutSeconds`，CLI `--upstream-header-timeout`，
  1s–10m）。原来的 45 秒会把合法的视频理解和转写请求变成 502。超时就是失败，不自动重试。
- 不重试 generation POST，不换账号、不用 credits，不把 429 解释成风控。上游非 200 保留 status、
  body（Chat 入口放在 `error.details`）和 Retry-After；凭据读取或首次 project discovery 失败返回本地 503。
- 传输失败仍是 502，但带 `diagnostic_id`、`failure_class`、`upstream_phase`、`elapsed_ms`，并与
  不含 URL / prompt / token 的 httptrace 日志关联；日志带 journal priority 前缀，适配 gizmo 只持久化
  notice / warning 的设置（`docs/incidents.md#agy-transport-generic-502`）。
- Files、cachedContents、batch、embeddings、TTS、生视频、Responses 服务端存储等已知入口返回 501；
  未知路径可能 404。网关不开通 GCP 产品、不花 credits、不把 OAuth 转发到客户端指定的 URL。

## gizmo 的凭据与登录 {#gizmo-login}

- 客户端 key：SOPS `secrets/clients/agy-proxy.yaml` 的 `agy-proxy/api_key`（读者：Hank、linwhite、
  fendada、gizmo、tank），运行时 `/run/secrets/agy-proxy/api_key`，经 systemd LoadCredential 传入。
  与 CLIProxy 的 key 不同。
- Google OAuth：`/var/lib/agy-proxy/oauth.json`，只由服务用户写；client ID / secret 来自 SOPS
  `agy-proxy/oauth_client`，不进源码或 store。快到期（不足一分钟）时服务自己刷新并原子写回 0600 文件
  （`--refresh-credentials`，只用于本服务登录生成的文件，不要对 CLIProxy 的共享 auth 文件开）。
  ACL 与 unit 优先级的坑：`docs/incidents.md#agy-gizmo-systemd-credentials`。

换账号或首次登录，在有浏览器的 Mac 上保持这个连接：

```sh
ssh -t -o ExitOnForwardFailure=yes \
  -L 51121:127.0.0.1:51121 hank@gizmo.inner.imdomestic.com \
  'sudo /nix/var/nix/profiles/system/sw/bin/agy-proxy-login'
```

终端打印 Google OAuth URL；用隐私窗口打开、选对账号并确认 consent，浏览器回到
`localhost:51121/oauth-callback` 经隧道到 gizmo。看到成功提示和预期 email 就可以退出，服务下一个
请求就读新文件，不用重启。已有 OAuth 文件时默认拒绝覆盖，换账号要加 `--force`。登录辅助以
transient service（`agy-proxy-login`）运行，十分钟超时；要取消就
`sudo systemctl stop agy-proxy-login`。本地端口被占时，`-L` 和 `--callback-port` 一起改。
不要把 callback URL、authorization code、refresh token 或 OAuth JSON 贴进聊天。
账号还得满足 Google / Antigravity 的地区、年龄、验证和资格要求；没有 project 时先去官方客户端开通。

取客户端 key（不要下载 OAuth 文件）并列出账号模型：

```sh
umask 077; mkdir -p ~/.local/state/agy-proxy
ssh hank@gizmo.inner.imdomestic.com 'sudo cat /run/secrets/agy-proxy/api_key' \
  > ~/.local/state/agy-proxy/client-key
curl -s -H "X-Goog-Api-Key: $(cat ~/.local/state/agy-proxy/client-key)" \
  https://gizmo.inner.imdomestic.com/agy/v1beta/models | jq -r '.models[].name'
```

401 是 key 错；未登录、凭据或 project 不可用是 503；Google 的 403 / 429 按它给的原因处理。
客户端的 base URL 要不要带版本前缀取决于客户端：Pi 1.5.2 必须设到 `/agy/v1beta`
（设到 `/agy` 会请求 `/agy/models/...` 得到 404）。

## 本机运行

```sh
nix run .#agy-proxy -- --listen 127.0.0.1:8319
CLOUD_CODE_URL=http://127.0.0.1:8319 agy        # 另一个终端：原生 agy 经 native 入口
```

- **native 入口**只放行观察到的 `/v1internal:*` 方法和非流式 `generateContent`，保留 body 字节、
  原生 UA、Google Bearer、SSE 分帧、错误和响应头；只改传输必需的 header，移除代理密钥、转发地址和
  幂等重放 header。上游固定为 daily，不能由请求指定，不跟随重定向。它不注入本机 OAuth：每个 native
  请求自己带 Google Bearer。配置了 `--client-key-file` 后 native 请求还必须带 `X-Agy-Proxy-Key`。
- **用本机账号跑 Gemini 入口**：`--keychain --client-key-file <file>`。macOS 上 consumer 登录在 Keychain
  的 service `gemini` / account `antigravity`（`go-keyring-base64:` 编码的 JSON），不是
  `~/.gemini/oauth_creds.json`。Keychain 模式只读 access token，不用 refresh_token，不回写；过期返回
  503，运行一次 agy 即可刷新。`--refresh-with-agy "$(command -v agy)"` 会在到期前一分钟内跑一次
  `agy models` 再读 Keychain（未做过真实到期验收，默认不开）。Linux 或显式导出的凭据用
  `--credential-file`（必须是私有普通文件）。

## 客户端

- **Pi（Hank）**：`home/hank/modules/pi/agy.nix` 声明原生 `agy/*`（`google-generative-ai`）和
  `agy-completions/*`（`openai-completions`），型号表在 `agy-models.nix`；默认开场用
  `systemPromptOptions.customPrompt` 设为一句 `you are a coding assistant`，项目上下文、AGENTS.md、
  skills 和实际工具声明不变；显式 `--system-prompt`、SYSTEM.md 优先。两个 provider 都发稳定的
  `X-Agy-Session-Id`。**Pi 1.5.2 的 Chat provider 不保留 `extra_content`，带工具的第二轮会 400**，
  所以 `agy-completions/*` 只是声明，默认别切过去。`scripts/check-pi-agy.sh`、`check-pi-compact-prompt.py`
  离线检查最终 payload。
- **Pi（linwhite）**：`home/linwhite/modules/pi/agy.nix` 只有原生 `agy/*`。Pi 1.5.2 的 Google 适配器只接受
  minimal / low / medium / high，所以 Hydrogen XHigh 经 `agy-google-xhigh` 适配器发送真实 `XHIGH`；
  扩展没加载时明确失败，不降成 High。回归：`bash scripts/check-pi-linwhite-agy.sh`。
- **Pi（fendada）**：`home/fendada/modules/pi/` 只有原生 `agy/*`，不带扩展，所以没有 Hydrogen XHigh、
  也不发 `X-Agy-Session-Id`（`docs/home/fendada-pi.md`）。
- **fx（Hank）**：`home/hank/modules/fx/` 的 `agy` 连接（`openai-chat-completions`，型号同 Pi 的
  `agy-models.nix`）。fx 0.0.18 只有 OpenAI / Anthropic 协议，Chat 也不回传 `extra_content`，2026-11-26
  实测带工具的第二轮 400，所以默认用 cliproxy 的 GPT，`agy` 只适合不调工具的单轮。
- **Max（maxx，tank）**：provider `agy-completions`，`protocol = "chat"`，key 在
  `/run/secrets/maxx/agy-completions-api-key`，retries=0（避免把 429 自动重放）。Max 的 Chat 解析会保留
  message / tool_call 上的未知字段，所以签名回放可用；Max 没有 Gemini 原生协议。
  型号在 `hosts/tank/maxx.nix`：Hydrogen 四档加 Argon / Carbon 的 low / medium / high
  （这两个系列没有 XHigh，不建假别名）。回归：`bash scripts/check-max-agy.sh`。

改客户端声明要激活对应 home（或让 Max 重载配置）并重开 / reload Pi；系统 switch 不会生效。

Pi 默认提示词与 Antigravity 泛化 429 的排查在 `docs/incidents.md#pi-antigravity-prompt-429`、
`#pi-agy-native-prompt-429` 和 `#pi-cliproxy-flash-compact-prompt`；网关不替换身份段、不加隐形字符、
不造签名，不能承诺消除 429。

## 原生协议画像

2026-11-16 用 `CLOUD_CODE_URL` 指向本地转发器观察 Nix 安装的 `agy` CLI 1.5.9（macOS arm64），
不需要装根证书或关 TLS 校验。`AGY_LLM_GATEWAY_URL` 是另一条自定义模型网关，会改变认证和模型发现，
不是 Cloud Code endpoint override；`--settings` 也不接受 `cloud_code_endpoint`
（误判见 `docs/incidents.md#agy-native-proxy-profile`）。桌面 App 的请求没有抓过。

- origin：`https://daily-cloudcode-pa.googleapis.com`。
- headers：`User-Agent: antigravity/cli/1.5.9 (aidev_client; os_type=darwin; arch=arm64; cl=…; auth_method=consumer)`、
  `Authorization: Bearer <Google access token>`、`Content-Type: application/json`；没有 `X-Goog-Api-Client`、
  request ID 或 session header。生成请求是 chunked body。
- 启动 / 控制面 POST：`loadCodeAssist`（`{"metadata":{"ideType":"ANTIGRAVITY"}}`）、`fetchAvailableModels`、
  `fetchAdminControls`、`fetchUserInfo`、`listExperiments`、`retrieveUserQuotaSummary`（都是
  `{"project":…}`）、`writeTrajectoryAcls`，生成走 `streamGenerateContent?alt=sse`。
- 生成 envelope：

  ```json
  {"project": "<project>", "requestId": "agent/<cascade-uuid>/<unix-ms>/<invocation-uuid>/1",
   "model": "gemini-4-hydrogen-high", "userAgent": "antigravity", "requestType": "agent",
   "request": {"sessionId": "<signed-decimal-string>", "contents": [], "systemInstruction": {…},
     "tools": [], "labels": {}, "generationConfig": {"maxOutputTokens": 262144,
       "thinkingConfig": {"includeThoughts": true, "thinkingLevel": "HIGH"}}}}
  ```

  原生 labels（`cascade_id`、`trajectory_id`、`used_claude` 等）是客户端的轨迹信息：适配入口不编造，
  收到的原样保留。SSE 外层有 `response`、`metadata`、`traceId`，内层有 `candidates`、`usageMetadata`、
  `modelVersion`、`responseId`；不能只留 candidate 0，也不能把缺 finishReason 的 EOF 补成 STOP。

与当时仓库里的 CLIProxy 8.0.73（`router-for-me/CLIProxyAPI@43806c86`）比较，CLIProxy 不是透明代理：

| 项目 | agy CLI / 本网关 | CLIProxy 8.0.73 |
| --- | --- | --- |
| UA | CLI 1.5.9；native 入口保留原值 | 默认 Hub 2.29.0，另有 manifest 刷新 |
| requestId | 原生斜杠分段 | 普通 agent 请求改成 `agent-UUID` |
| maxOutputTokens | 262144 被接受；适配入口保留调用者的值 | 非 Claude builder 删掉这个字段 |
| tools schema | 不清理 | 清理 schema、去 enum、规范函数名 |
| 历史 | 不改 role、不重排、不补空 turn | 配对、role 和边界修正 |
| thoughtSignature | 当 opaque 字段保留 | sanitize、删除或迁移，可能补 bypass |
| SSE | native 原字节；Gemini 只解外壳 | 解包、转换 / 聚合，部分路径合成终止 |

这些差异不证明 Google 是因为哪一项拒绝了之前的请求。

## 测试

默认测试不联网、不读真实 OAuth：

```sh
cd pkgs/agy-proxy && go test -race ./... && go vet ./...
```

覆盖 native 字节保真、认证与固定路径、header 防泄漏、工具 / 签名 / schema 不改写、多候选与多行 SSE、
EOF 与取消、不重试 429、Chat 与 Responses 转换、签名密文防篡改、multipart 媒体、大小上限和 token
计数不静默忽略字段。会消耗账号额度的 live 测试要显式打开：

```sh
AGY_CHAT_LIVE_URL=https://gizmo.inner.imdomestic.com/agy/v1beta \
AGY_CHAT_LIVE_KEY_FILE="$HOME/.local/state/agy-proxy/client-key" \
  go -C pkgs/agy-proxy test -run '^TestChatLiveThroughGemini$' -v -timeout 3m .
```

真实媒体验收用合成素材（PNG、MP4、TTS WAV），不要用用户的图片或声音。
