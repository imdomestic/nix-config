# agy-proxy：原生 Antigravity 透传与 Gemini API

`pkgs/agy-proxy/` 是独立的 Go 程序，无第三方依赖，不复用 CLIProxy 的
translator/executor。当前是 **loopback 原型**，没有替换 gizmo 的 CLIProxy，
没有启用常驻服务，也没有修改 Pi / Max 的模型路由。

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

仓库当前求值版本为 **CLIProxyAPI 8.0.73**，来自 `llm-agents`，不是
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

## 两种入口

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
`id_token_email`、`writer_id`。程序仅读取 consumer token，不输出 email，
不解析或使用 refresh_token，不回写 Keychain。

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
是 private regular file；不接受 group/world 可读权限。程序每次重新读，
**不做独立 OAuth refresh、回写或自动 onboardUser**。不要把凭据写到 Nix
表达式、Nix store、环境日志或 git。此路径没有 Linux 实机上游验收。

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

## 验证与范围

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

包输出提供 aarch64-darwin、aarch64-linux、x86_64-linux。没有 Home Manager
激活或系统部署。以后若要变成 fleet 服务，先补原生模块选项、运行时 secrets、
访问控制/TLS、压力与真实 token 到期测试，再决定 placement；不要直接把
loopback 原型暴露到 LAN。TLS 栈使用 Go 默认校验和协商，没有证明 TLS
指纹与 agy 完全一致，也没有据此关闭 HTTP/2。
