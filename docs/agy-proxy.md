# agy-proxy：原生 Antigravity 透传与 Gemini API

`pkgs/agy-proxy/` 是独立的 Go 程序，无第三方依赖，不复用 CLIProxy 的
translator/executor。后端只监听 loopback；gizmo 的独立 NixOS 服务经现有
Tailscale HTTPS 暴露 `/agy/v1beta/`，不替换 CLIProxy 的 `/v1/`，也不修改
Pi / Max 路由。v0.2 增加独立浏览器 OAuth 登录与服务自己凭据的原子刷新。
v0.3 的可选 [OpenAI Chat Completions 兼容层](agy-chat-completions.md) 已在
gizmo 开启，Max 已加载独立 `agy-completions/*`，原生 Gemini 入口不变。
v0.4 新增 Responses、token 计数与图片/文件音频接口，支持范围和实际
验收状态统一见 [API 能力表](agy-api.md)。

## 2026-11-19 · linwhite Pi 的 Hydrogen XHigh 映射

encore 已加载 linwhite 的 agy 配置，但仍显示旧 CLIProxy Hydrogen 四档；
该网关当前目录不含这些型号，选择它们会报 400 unknown provider。linwhite
现从 CLIProxy 只移除这四条，保留 Flash 和其他模型；激活时仅迁移明确
指向旧 Hydrogen 的默认模型与 scoped patterns，不改其他选择或历史会话。

先前只验证了 Flash，误以为 Pi 的 Google 适配器能发送 XHIGH。Pi 1.5.2
实际上只接受 minimal/low/medium/high，静态的 `xhigh -> xhigh` 在发送前
就抛错。linwhite 的 `agy-google-xhigh` 适配器限定于 agy Hydrogen XHigh，
借用 Pi 原生 Google 流处理和签名回放，仅在请求中发送真实 `XHIGH`；
扩展未加载时明确失败，不静默降为 High。离线真实 Pi 两轮工具测试验证了
请求与签名回放、其他 High 型号不变及无扩展时不发请求。

真实 gizmo 请求已越过 Pi 错误，但 Google 返回 503
`MODEL_CAPACITY_EXHAUSTED`；这不是适配器或认证错误，暂不能声称模型可用。
Flash High 的此前真实工具测试通过；账号目录和上游容量仍会变化。
`bash scripts/check-pi-linwhite-agy.sh` 覆盖上述回归。修改须等待独立 home
激活及 Pi reload/重启，已保存的历史会话需重新选 `agy/*`。

## 2026-11-19 · linwhite 接入共享网关

linwhite 的独立 home 新增 `agy/*` 原生 Gemini provider，保留原有 CLIProxy
型号和默认选型；没有新增 Pi Chat 兼容入口。`secrets/clients/agy-proxy.yaml`
增加 linwhite 的 age 收件人，既有网关 key 未轮换，Google OAuth 仍只在 gizmo。
Pi 扩展对 agy 模型使用简短默认开场与稳定 session header，同时保留原有
CLIProxy 提示词行为。简短开场替代 Pi 默认工具规则文本，但项目上下文和
实际工具声明保留；显式自定义提示词不覆盖。

实测账号目录返回 30 个 Gemini ID，包括 Hydrogen 四档；静态声明仍是与
Hank 对应的 8 款，以实时目录为准。用生成的正式 Pi 扩展、完整仓库上下文
和只读 `read` 工具测试，Flash High 两轮成功；关闭了 MCP、skills 和 prompt
templates。Hydrogen High 返回上游 503 `MODEL_CAPACITY_EXHAUSTED`，不能把
目录中出现视为容量可用。未激活 home；后续单独激活并重开或 reload Pi。
回归检查：`bash scripts/check-pi-linwhite-agy.sh`。

## 2026-11-16 · 本机原生协议画像

实测对象：Nix 安装的 `agy` **1.5.9**，macOS arm64。另有桌面 App
**2.32.1**；本次没有捕获桌面请求，不能把 CLI 画像称为 Hub 的画像。

CLI 的 `CLOUD_CODE_URL` 可以覆盖 Cloud Code origin。用临时本地转发器
转到原 origin 即可观察，不需要安装根证书、修改 App 或关闭 TLS 校验。
注意：`AGY_LLM_GATEWAY_URL` 是另一条自定义模型网关路径，会改变认证和
模型发现；它不是 Cloud Code endpoint override。`--settings` 也不接受
`cloud_code_endpoint`。排查中的误判见
[事故记录](incidents.md#agy-native-proxy-profile)。

确认的 origin：`https://daily-cloudcode-pa.googleapis.com`。原生 headers：

```text
User-Agent: antigravity/cli/1.5.9 (aidev_client; os_type=darwin; arch=arm64; cl=1021519450; auth_method=consumer)
Authorization: Bearer <Google access token>
Content-Type: application/json
Accept-Encoding: <present; value not retained>
```

本次未看到 generation 的 `X-Goog-Api-Client`、自定义 request ID header 或
session header。生成请求使用 HTTP chunked body；HTTP 分块方式不是 JSON
的一部分，反代可以重新分块，但不能丢掉 body。

启动/控制面观察到以下 POST：

- `loadCodeAssist`：`{"metadata":{"ideType":"ANTIGRAVITY"}}`
- `fetchAvailableModels`、`fetchAdminControls`、`fetchUserInfo`、
  `listExperiments`、`retrieveUserQuotaSummary`：`{"project":"<project>"}`
- `writeTrajectoryAcls`：`{"trajectoryId":"<uuid>"}`
- `streamGenerateContent?alt=sse`：下面的生成 envelope

Hydrogen High 的最小原生请求外壳如下；实际 prompt、project、UUID、token
没有进入仓库：

```json
{
  "project": "<project>",
  "requestId": "agent/<cascade-uuid>/<unix-ms>/<invocation-uuid>/1",
  "model": "gemini-4-hydrogen-high",
  "userAgent": "antigravity",
  "requestType": "agent",
  "request": {
    "sessionId": "<signed-decimal-string>",
    "contents": [],
    "systemInstruction": {"role": "user", "parts": []},
    "tools": [],
    "labels": {},
    "generationConfig": {
      "maxOutputTokens": 262144,
      "thinkingConfig": {"includeThoughts": true, "thinkingLevel": "HIGH"}
    }
  }
}
```

实测原生 body 41,436 bytes，systemInstruction 一段，文本长度 19,657
字符，14 个工具各占一个 `functionDeclarations` group。这是当次 plan
会话的数目，不是固定协议要求；反代没有复制原生系统提示或工具集。

原生 labels 的键：`cascade_id`、`last_step_index`、`model_enum`、
`request_id`、`root_cascade_id`、`trajectory_id`、`used_claude`、
`used_claude_conservative`、`used_non_gemini_model`。它们是客户端实际轨迹
信息，**适配入口不会编造这些 labels**。收到的原生 labels 则原样保留。

SSE JSON 外层含 `response`、`metadata`、`traceId`；内层含 `candidates`、
`usageMetadata`、`modelVersion`、`responseId`。不能只保留 candidate 0，
也不能把缺少 finishReason 的 EOF 补成成功 STOP。

账号模型目录当时为 33 条，22 条 `gemini-*`；Hydrogen 有四个真实 ID，
不是一个 XHigh ID 的四个别名。目录给 Hydrogen High 的输出上限是
262,144，Flash High 为 65,536。这些是目录上限，不等于每个请求都会
输出这么多，也不是订阅账单或额外额度承诺。

### 与仓库当前 CLIProxy 的差异

首次调查时仓库求值版本为 **CLIProxyAPI 8.0.73**，来自 `llm-agents`，不是
nixpkgs。对应公开源码 commit：
[`43806c865da7d47f9252316e95e315ad9f885b84`](https://github.com/router-for-me/CLIProxyAPI/tree/43806c865da7d47f9252316e95e315ad9f885b84)。

| 项目 | agy CLI 实测 / 本反代 | CLIProxy 8.0.73 源码行为 |
| --- | --- | --- |
| UA | CLI 1.5.9；native 入口保留原值 | 默认 Hub 2.29.0，另有 manifest 刷新 |
| requestId | 原生斜杠分段；native 保留 | 普通 agent 请求改为 `agent-UUID` |
| maxOutputTokens | 实测 262144 被接受；适配入口保留调用者值 | 非 Claude builder 删除该字段 |
| tools schema | 不清理约束、enum、union 或函数名 | 清理 schema、移除 enum、规范函数名 |
| 历史 | 不改 role、不重排 tool response、不补空 turn | pairing、role 和边界修正 |
| thoughtSignature | 当作 opaque 字段保留 | sanitize、删除/迁移、可能补 bypass |
| SSE | native 原字节透传；Gemini 仅解 envelope | 解包、转换/聚合、部分路径合成终止信息 |

源码定位：`internal/runtime/executor/antigravity_executor_request.go`、
`antigravity_executor.go`、`antigravity_executor_stream.go`，
`internal/translator/antigravity/gemini/antigravity_gemini_{request,response}.go`，
`internal/signature/gemini_sanitize.go`，`internal/misc/antigravity_version.go`。

这些差异证明 CLIProxy **不是透明代理**，不证明 Google 因哪项差异拒绝了
此前的请求。原生身份段与泛化 429 的既有证据仍见
[之前的记录](incidents.md#pi-antigravity-prompt-429)。本程序不替换用户身份
段、不添加隐形字符、不制造签名绕过；不能承诺消除所有 429。

## 原生与兼容入口

### 原生透传：不读取本机凭据

```sh
nix run .#agy-proxy -- --listen 127.0.0.1:8319
# 另一个终端，正常使用自己已经登录的 agy：
CLOUD_CODE_URL=http://127.0.0.1:8319 agy
```

只允许已观察的 `/v1internal:*` 方法，以及非流式 `generateContent`。
保留 body 字节、原生 UA、Google Bearer、SSE framing、错误与 response
headers；仅修改传输必要 headers，移除代理密钥、转发地址和幂等重放
headers。上游固定 daily，不能由请求指定 URL，不跟随重定向。

这不是匿名订阅网关：每个 native 请求必须自己携带 Google Bearer；它
不会注入本机 OAuth。未配置 client key 时仅供本机可信进程诊断。
配置 `--client-key-file` 后 native 请求还须携带 `X-Agy-Proxy-Key`；普通
`CLOUD_CODE_URL=... agy` 不会自动添加这个 header。

### Gemini API：显式启用本机账号

macOS consumer 登录实际存放在 Keychain 的 **service `gemini` / account
`antigravity`**；不是 `~/.gemini/oauth_creds.json` 的 Gemini CLI 登录。
Keychain 值是 `go-keyring-base64:` 编码的 JSON，含 `token`、`auth_method`、
`id_token_email`、`writer_id`。Keychain 模式仅读取 consumer token，不输出
email，不解析或使用 refresh_token，不回写 Keychain。

```sh
umask 077
mkdir -p ~/.local/state/agy-proxy
openssl rand -hex 32 > ~/.local/state/agy-proxy/client-key

nix run .#agy-proxy -- \
  --keychain \
  --client-key-file ~/.local/state/agy-proxy/client-key
```

可另加 `--refresh-with-agy "$(command -v agy)"`：距到期不足一分钟时，
在锁内执行一次最多 45 秒的原生 `agy models`，再读 Keychain。清掉子进程
的 `CLOUD_CODE_URL` / `AGY_LLM_GATEWAY_*`，防止递归请求代理。原生 agy
仍是唯一 refresh-token writer。**该自动刷新路径尚未做真实到期验收**；
默认不启用它，过期返回 503，用户可自己运行 agy 完成刷新。

Linux 或显式导出凭据可用 `--credential-file /private/oauth.json`，代替
`--keychain`。接受上述原生 consumer wrapper，或带 `access_token`、
可选 `project_id`、RFC3339 `expiry` / CLIProxy `expired` 的 JSON。文件必须
是 private regular file；不接受 group/world 可读权限。程序每次重新读。
默认仍只读；v0.2 的 `--refresh-credentials` 只供本服务通过独立 `login`
生成并拥有的文件使用，且要求 `--oauth-client-file` 私有运行时 JSON；距
到期不足一分钟时刷新并原子写回 0600 文件。
不要对 CLIProxy 的共享 auth 文件打开它，也不要把凭据写到 Nix 表达式、
Nix store、环境日志或 git。不自动 onboardUser、购买额度或启用 credits。

API：

- `GET /v1beta/models`、`GET /v1beta/models/<real-id>`：按账号实时发现，
  只列 `gemini-*`，不静态猜测新型号；当前不支持分页 query。
- `POST /v1beta/models/<real-id>:generateContent`
- `POST /v1beta/models/<real-id>:streamGenerateContent?alt=sse`
- `GET /healthz`：仅进程健康，不代表凭据/上游可用。

客户端可用 `Authorization: Bearer <proxy-key>` 或 Google SDK 常用的
`X-Goog-Api-Key: <proxy-key>`。两者同时出现时必须相同。拒绝 URL 中的
`?key=...`，不会把客户端 key 转发给 Google。

Gemini 请求使用 REST 的 camelCase 字段。仅加 project、model、userAgent、
requestType、requestId 外壳；内层除缺少 sessionId 时补该字段，不改其
JSON 语义。不会自动替客户端选 thinkingLevel、改 maxOutputTokens、
添加原生 prompt 或推测工具历史。JSON 空白/escape 表示可能重新编码，
不能把此入口称为 body 字节透传。

请求中已有 `sessionId` 优先；否则用客户端 `X-Agy-Session-Id`，都没有
则每次独立生成。多轮工具调用的客户端应发送稳定、独立的 session header，
并原样回放返回的 model content / signature carriers，而不是只抽出
functionCall 后丢弃签名。可用 `X-Agy-Request-Id` 显式携带请求 ID；缺省
ID 模仿分段格式但不是实际 agy trajectory，不声称它是幂等键。

SSE 支持多行 data、event/id/retry、comments、未知内层字段和多 candidates。
只解 `response` 外壳；外层 traceId/metadata 不在 Gemini response 中，
需要它们时用 native 入口。独立 error/metadata-only frame 不伪造为成功。
截断帧/读取失败会中断连接，不补 STOP / DONE；取消请求会取消上游。
不做 credential pool、credits fallback、冷却或自动重放 generation POST。
生成请求的非 200 保留上游 status、body 和 Retry-After，不解释成已证实的
风控；凭据读取或初次 project discovery 失败则返回本地 503。

## 最初原型验证与范围

2026-11-16，编译出的本程序临时运行、随后退出：

| 验收 | 结果 |
| --- | --- |
| 原生 agy 经 native 入口 | exit 0，收到指定探针文本 |
| 本机 Keychain → 动态 Gemini 目录 | 200，22 条 Gemini，Hydrogen 四档都在 |
| Hydrogen High Gemini JSON | 200，收到指定文本；一次约 3.0 秒到响应 headers |
| Gemini SSE | 200，3 frames，拼接输出等于探针，原生 STOP |
| 工具第一轮 | 200，`proxy_probe` 调用且原生 thoughtSignature 存在 |
| 原 model content / 签名回放 + functionResponse | 200，第二轮收到指定文本 |

探针中的工具只由测试脚本返回固定 `ok`，没有执行 shell 或修改用户文件。
这不是完整 Pi 工作负载、所有模型/多模态或过期刷新的验收。

离线：

```sh
cd pkgs/agy-proxy
go test -race ./...
go vet ./...
# 回到仓库根目录：
nix build .#agy-proxy
```

测试覆盖 native body/SSE 字节保真、chunked、认证和固定路径、headers
防泄漏、跨域 redirect 不带 token、工具/签名/schema/输出上限不改写、
多候选、多行 SSE、EOF、不重试 429、断连取消、账号 project 隔离、私有
凭据格式/权限和 body 上限。

包输出提供 aarch64-darwin、aarch64-linux、x86_64-linux。以上是最初原型
的本机验收，不是新 Google 账号的 gizmo 实机推理验收。TLS 栈使用 Go
默认校验和协商，没有证明 TLS 指纹与 agy 完全一致，也没有据此关闭 HTTP/2。

## gizmo 服务与新 Google 账号登录

- 原生模块：`system/modules/agy-proxy/default.nix`；host 配置：
  `hosts/gizmo/agy-proxy.nix`。后端 `127.0.0.1:8319`，独立 `agy-proxy` 用户，
  private state directory，512 MiB memory ceiling。
- HTTPS：`https://gizmo.inner.imdomestic.com/agy/v1beta`，仅已有 Tailscale
  TLS 443 listener；不开放额外 LAN/公网端口，不暴露 native/control/login。
- 独立客户端 key：SOPS `secrets/clients/agy-proxy.yaml` 的 `agy-proxy/api_key`，
  runtime `/run/secrets/agy-proxy/api_key`；systemd LoadCredential 私有传入。
  不复用 CLIProxy key，旧账号凭据与客户端路由不变。
- 新 OAuth：`/var/lib/agy-proxy/oauth.json`，登录和刷新只由该服务用户写。
  scopes 按 Antigravity installed-app 协议使用；client ID/secret 通过
  SOPS `agy-proxy/oauth_client` 私有 JSON 注入，不硬编码在源码或 Nix store。
  登录辅助通过临时 `agy-proxy-login.service` 的 LoadCredential 注入，进程仍
  以 `agy-proxy` UID 写 OAuth，不放宽 SOPS 父目录权限。直接 `agy-proxy login`
  也需 `--oauth-client-file`。Google 密码只在用户自己的浏览器输入，不给服务器
  或代理。

### 1. 开 SSH 回调隧道并启动登录

在有浏览器的 Mac 终端运行，保持连接：

```sh
ssh -t -o ExitOnForwardFailure=yes \
  -L 51121:127.0.0.1:51121 hank@gizmo.inner.imdomestic.com \
  'sudo /nix/var/nix/profiles/system/sw/bin/agy-proxy-login'
```

使用启动默认 profile 的绝对路径，当前若尚未完整切换新系统也可运行；
完整激活后也可以直接 `agy-proxy-login`。本地端口被占用时，选另一个
callback port 并同时修改 SSH `-L` 与命令 `--callback-port`。

终端会打印 Google OAuth URL。用隐私窗口打开，明确选择**新创建的账号**，
阅读并确认 Google consent。浏览器回到 `localhost:51121/oauth-callback`
后经 SSH 到 gizmo；state、PKCE 和 callback 只在这次登录内使用。
看到成功提示及预期 email 后即可退出 SSH。服务下一次请求就读到新文件，
不需要重启，不改本机 agy 的 Keychain。

默认拒绝覆盖已有 OAuth 文件；需要换账号时，明确加 `--force` 再走完整
浏览器登录。辅助以 transient service 运行；需主动取消时，另开终端运行
`ssh hank@gizmo.inner.imdomestic.com 'sudo systemctl stop agy-proxy-login'`。
登录超时十分钟；不要把 callback URL、authorization code、
refresh token 或 OAuth JSON 贴进聊天。

新账号仍须满足 Google / Antigravity 的地区、年龄、验证、资格和条款要求。
如无 Antigravity project 或 Google 返回不符合资格，先去官方网页或原生
客户端完成正常开通；代理不自动开通付费产品、不绕过账号验证或限额。

### 2. 把客户端 key 安全取到本机

只取代理调用 key，**不要下载 OAuth 文件**：

```sh
umask 077
mkdir -p ~/.local/state/agy-proxy
ssh hank@gizmo.inner.imdomestic.com \
  'sudo cat /run/secrets/agy-proxy/api_key' \
  > ~/.local/state/agy-proxy/client-key
chmod 600 ~/.local/state/agy-proxy/client-key
```

该 key 与旧 CLIProxy key 不同。应用选 Gemini 协议；base URL 是否要带
版本前缀取决于客户端，不能假设 SDK 自动补版本。**Pi 1.5.2 实测必须设
`https://gizmo.inner.imdomestic.com/agy/v1beta`**；设到 `/agy` 会直接请求
`/agy/models/...` 并得到 404。直接 REST 使用 `/agy/v1beta/models/...`。
认证用 `X-Goog-Api-Key` 或 Bearer，不要放到 URL query。

### 3. 验证账号模型目录

```sh
python3 - <<'PY'
import json
from pathlib import Path
from urllib.request import Request, urlopen
key = (Path.home() / '.local/state/agy-proxy/client-key').read_text().strip()
req = Request('https://gizmo.inner.imdomestic.com/agy/v1beta/models',
              headers={'X-Goog-Api-Key': key})
with urlopen(req, timeout=45) as response:
    for model in json.load(response)['models']:
        print(model['name'])
PY
```

以返回的真实 ID 为准，不假设新账号一定有 Hydrogen 或全部档位。
401 是客户端 key 错；未登录/凭据或 project 不可用会返回 503；Google 的
403/429 仍需按它给出的资格/额度响应处理。离线测试覆盖登录、刷新和竞态，
真实新账号 consent、token 到期及实机模型调用须在用户完成登录后验收。

## 2026-11-18 · Gemini 默认开场改为一句

Hank 的 `agy/*`、`agy-completions/*` 使用 Pi 原生结构化
`systemPromptOptions.customPrompt` 设置默认开场：

```text
you are a coding assistant
```

不再使用此前的两段 Antigravity 身份。这里与已实测的 `--system-prompt`
走同一条构建路径，而不是只改首句却保留 Pi 原来那套默认段。Pi 自带的
默认 tools/rules/docs 文本模板由 customPrompt 替代，**实际 provider tool
schemas 不变**；AGENTS.md、skills、appendSystemPrompt 和其他扩展添加的
custom sections 仍由 Pi 构建器保留。

仅匹配 Hank 配置中的这两组 provider/模型；GPT、Rewind、NInfer、其他
provider 和其他账户不改。显式 `--system-prompt`、SYSTEM.md 或先前扩展
设置的 forceSystemPrompt 都尊重，即使文本恰好与 Pi 默认身份相同。
稳定 session header 不变，没有添加签名、UA 或不可见字符。

验证：作用域/显式覆盖/上下文对象单测、组合扩展两代测试通过；新增
`check-pi-compact-prompt.py` 用真实 Pi 向 loopback mock 发 HTTP，核对
Gemini/Chat 最终 payload 的准确开头、项目/追加/自定义 sections、read
工具声明及其他 provider 不受影响，全程离线。

临时加载 Nix 新生成的正式扩展（没有额外传 `--system-prompt`），原生
`agy/gemini-3.8-flash-high` 在完整仓库上下文中 read fixture 两轮均成功，
约 12.58 秒。未做完整 Home Manager 激活、未手工更换扩展 symlink、
未改用户默认型号；后续 home 激活并 reload/重开 Pi 才持久生效。

**同次发现独立的模型目录变化：** 原生 `gemini-4-hydrogen-high` 返回
Google 404 / NOT_FOUND。目录当时有 16 条 Gemini，已不列 Hydrogen 四档，
只剩 `gemini-4-hydrogen-disabled`、`gemini-4-hydrogen-sonar`。这里不替用户
切换默认、不把 disabled 当可用、不猜 sonar 的能力，也不把 404 归咎于
提示词。用户若仍选旧 Hydrogen，单改开场无法恢复一个上游已不再列出的
型号；目前已实际通过该配置验证的是 Flash High。

## Pi 与 Max 接入

Gemini 是 Google 原生的 REST/JSON + SSE API：请求用 `contents`、`parts`、
`systemInstruction`、`functionDeclarations`，响应用 `candidates`，工具
历史携带 `functionCall`、`functionResponse` 与 opaque `thoughtSignature`。
它不是 OpenAI `/v1/chat/completions` 或 `/v1/responses` 的另一个 URL。

Pi 1.5.2 已有 `google-generative-ai` provider。Hank 的声明入口是
`home/hank/modules/pi/default.nix`，也可在自己的 host home module 通过
`my.pi.providers.agy` 增补，不要覆盖整份 `models.json`。Hank 现在通过
`home/hank/modules/pi/agy.nix` 声明该 provider，型号表在 `agy-models.nix`。
下面是只加 High 的简化示例：

```nix
my.pi.providers.agy = {
  name = "agy";
  baseUrl = "https://gizmo.inner.imdomestic.com/agy/v1beta";
  api = "google-generative-ai";
  apiKey = "!cat ${config.sops.secrets."agy-proxy/api_key".path}";
  models = [{
    id = "gemini-4-hydrogen-high";
    name = "agy/gemini-4-hydrogen-high";
    reasoning = true;
    input = ["text" "image"];
    contextWindow = 1048576;
    maxTokens = 65536;
    thinkingLevelMap = {
      off = null; minimal = null; low = null; medium = null;
      high = "high"; xhigh = null; max = null;
    };
    cost = { input = 1.5; output = 7.5; cacheRead = 0.075; cacheWrite = 0; };
  }];
};
```

上例成本是公开 API 的估算，不是订阅账单；输出预算是保守选择，目录上限
仍是 262144。其余真实预设分别增补模型 ID，不靠 changing effort 假装
切换预设。home 修改须单独激活，系统 switch 不生效。声明中已移除 Hank
Pi 的全部 8 个 CLIProxy Gemini 条目，GPT、Rewind、OpenCode 与 NInfer
不变；Max、其他账户和 OpenCode 自己的 Gemini 配置没有在此次迁移中改动。

新账号在 gizmo 的实测：Hydrogen High JSON 200（约 5.34 秒）、Flash High
SSE 200（约 6.22 秒）、两轮工具调用 200（约 7.12/4.16 秒，原始签名保留）。
Pi 用隔离临时配置、`google-generative-ai`、上述完整 base URL 的单轮
streaming 请求也成功（约 4.63 秒），未改用户配置或运行完整项目上下文。
没有以修改 expiry 等方式强制刷新，真实 token 到期刷新仍待自然发生后验收。

当前 pin 的 Rust Max **没有 Gemini-native protocol**：
`crates/max/src/config.rs` 的 `ProtocolName`、`max-core/src/item.rs` 的
`Protocol` 只有 Chat / Responses；`max-llm/src/client.rs` 也只发这两种
请求。不能在 `hosts/tank/maxx.nix` 单加 `protocol = "gemini"` 就连接。
推荐在 Max 上游增加第三种协议，完成请求编码、SSE/usage/错误解析、
model content/signature 原样持久化及图片/视频/工具回放测试，再加独立
`agy` provider。VM 内 Pi 的链路还要更新 `crates/max/src/service/forward.rs`
的 `/llm` 模型描述及 Gemini 路径转发，不是只改主聊天 client。
另一路是 v0.3 的显式 [Chat Completions 兼容入口](agy-chat-completions.md)：
Max 可继续使用现有 Chat 协议和 opaque fields，不必先改 Gemini-native。
该入口的模块默认关闭，gizmo 显式开启且 Max 已加入 `agy-completions/*`；
它会明确拒绝不支持或丢失签名的历史，不是把 OpenAI 格式冒充成无损 native
透传。Hank Pi 也加入同名声明，但 1.5.2 Chat provider 丢签名的工具回放边界
尚待适配，见兼容层文档，不应据此把 Pi 默认切到 Chat。

## 2026-11-17 · Hank Pi 的 provider 迁移

`my.pi.providers.agy` 经 `agy.nix` 加入，模型名与 provider/id 都是
`agy/gemini-…`；保留原先 4 条 Flash/Lite 和 Hydrogen 的真实四档，不添加
目录中标记 disabled 或未经选定的别名。Pi 上下文仍是 1M，输出预算
65535/65536，价格沿用公开 API 估算。

- 调用 key **未轮换**：从 gizmo host secret 移到独立 client SOPS 文件，
  `.sops.yaml` 只允许 Hank 的 keys 和 gizmo 解密。Hank home 使用原生
  sops option 注入 secret 路径，不依赖每台手工下载；Google OAuth 不分发。
  gizmo 的 runtime key 路径保持不变，本次未重启或激活 gizmo。
- 既有 Antigravity 身份两段保留，扩展 scope 改为 agy；只改精确的 Pi 默认
  开头，AGENTS.md / 工具规则 / 自定义身份不覆盖。增加稳定的
  `X-Agy-Session-Id`，跨两轮请求使用 Pi 的 session UUID。
- `migrate-pi-agy.py` 仅在 home 激活时把已移除的 CLIProxy Gemini 默认选择
  和显式 Gemini scoped patterns 转到 agy；固定预设的旧 effort 校正到该档。
  自定义默认、其他 provider、历史会话不改，第二次执行不会覆盖新选择。
- 静态比较确认：新 agy 恰好覆盖删除的 8 个 ID；剩余 CLIProxy 和 NInfer
  配置语义与迁移前完全相同。`check-pi-agy.sh`、提示词、组合扩展两代离线
  测试及迁移脚本 5 项单测通过；praxic/tank/taipan/wsl home 求值通过。
- Home dry-build 仍需要构建 Node 等依赖，**未做完整 home 激活**，也没有
  手工替换当前运行的 `models.json` / extension。当前会话和默认选择要等
  home 激活与 Pi reload/重开后才跟随新声明。

### 实际请求的边界

新的 XHigh 模型 ID + native `thinkingLevel: "XHIGH"` 短请求返回 200；
这证明字段被接受，不是计算档位的独立测量。迁移前的短 Pi smoke test
以及直接 Gemini 的签名工具回放均已通过（上文）。

但本次实际 Pi 的默认提示词 + `read` 工具请求，无论完整仓库上下文还是
隔离的无 AGENTS.md 会话，都返回 Google 429 / RESOURCE_EXHAUSTED。
离线捕获实际 HTTP body 确认 Antigravity 身份前缀、HIGH、Gemini 原生
字段和 session header 都已发送；不能把这个 429 解释成漏装身份扩展。
同一时段同模型短请求仍返回 200。仅降输出上限至 8192，或将工具 schema
字段从 parametersJsonSchema 改为 parameters 的对照也仍为 429，不能
当作已修复或据此断言账号额度/风控的具体原因。原生 user role 已由 Pi
发送；移除工具但保留 systemInstruction 仍是 429，只作为对照移除
systemInstruction 则 200。没有据此在正式配置里删除系统提示词。

**本次是声明迁移与回归验证，不声称完整 Pi 工具工作负载已排除 429。**
未为通过测试更换账号、抹掉项目规则、伪造 thoughtSignature 或自动重放
代理请求；后续定位应保留这一边界。

## 2026-11-16 · gizmo 部署验收

声明提交 `7f8f021a`，systemd credential ACL 修复 `4754e893`，登录辅助的
LoadCredential 修复 `784e2d3f`；统一在 r6s 构建（`--max-jobs 1 --cores 2`），
gizmo 不编译。版本 **0.2.1**。

- `agy-proxy`、nginx、旧 CLIProxy 全部 active；后端仅 `127.0.0.1:8319`。
- Mac 验证真实 TLS：新 HTTPS 不带 key 为 401，独立 key 为 503（还没有
  新 Google OAuth），`/agy/v1internal:loadCodeAssist` 为 404。
- 旧 `/v1/models` 认证边界仍为 401；CLIProxy PID `3000392` 未改变，仍跑
  8.0.69，没有趁此重启或换掉它的 Google 登录。
- 在 gizmo 实测启动登录辅助：已读到 runtime OAuth client，回调监听正常，
  URL 含 PKCE S256 和账号选择；探针在 consent 前取消，未产生 OAuth 文件。
- 自动回退 timers 已取消；没有遗留监听 51121/51122 的探针。

gizmo 原先已积压内核升级。本次不重启：加载内核仍 **6.18.57**，
`/run/current-system` 仍为
`/nix/store/17kx445cffhd0yw7f0j8nbsx3ij0am0x-nixos-system-gizmo-26.05.20261108.ac588ef`。
完整新配置已持久设为下次启动：
`/nix/store/ihcb5zc9vfzvm54m872amb21szz4h75i-nixos-system-gizmo-26.05.20261113.f1e5c35`，
含 6.18.63 和 CLIProxy 8.0.74；这里只启用本任务的服务和路由。

当前 runtime 激活层是 `/run/systemd/system/agy-proxy.service` 和
`/run/systemd/system/nginx.service.d/90-agy-proxy.conf`（ExecStart/ExecReload
来自同一声明产物）。后者必要，因为旧 `/etc/systemd/system` 整体是 store
symlink，且 `/etc` whole unit 优先于 `/run` whole unit；不能用同名 `/run`
unit 假装已切换 nginx。重启时这两层自然消失，由新系统声明接管，不要
把当前运行代误报成已完整升级。回退与权限排查见
[事故记录](incidents.md#agy-gizmo-systemd-credentials)。
