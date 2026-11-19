# agy-proxy v0.4 API 能力与边界

这是 Antigravity 订阅生成接口上的适配网关，不是 Google Developer API、
Vertex 或 OpenAI 全套服务的镜像。新增接口必须确实调用上游并返回真实
结果；不创建假的 Files、缓存命中、batch、向量或后台 job。

现有两个 base URL 不变：

- Gemini：`https://gizmo.inner.imdomestic.com/agy/v1beta`
- OpenAI 兼容：`https://gizmo.inner.imdomestic.com/agy/v1`

使用原有代理 key（Bearer 或 X-Goog-Api-Key）；不向客户端分发 Google
OAuth。所有新增入口继续只经现有 nginx 路由，后端只监听 loopback，
不开放额外公网端口。

## 接口

| 方法 / 路径（相对各自 base URL） | 行为 |
| --- | --- |
| `GET /models`、`GET /models/<id>` | 按账号发现真实 Gemini 模型 |
| Gemini `POST /models/<id>:generateContent` | 原生 parts、工具、媒体、签名透传 |
| Gemini `POST /models/<id>:streamGenerateContent?alt=sse` | 原生流式生成，只解外壳 |
| Gemini `POST /models/<id>:countTokens` | 真实上游 contents-only 计数 |
| OpenAI `POST /chat/completions` | 既有 Chat 转换入口 |
| OpenAI `POST /responses` | 无状态 Responses，全历史输入与加密 replay blob |
| OpenAI `POST /images/generations` | Gemini 图像型号生成真实图片，b64_json |
| OpenAI `POST /images/edits` | multipart 图片 + prompt，生成编辑结果 |
| OpenAI `POST /audio/transcriptions` | 文件音频交给 Gemini 转写 |
| OpenAI `POST /audio/translations` | 文件音频交给 Gemini 翻译成英文 |
| `GET /capabilities` | 本网关自定义的实现能力/限制说明，不是账号权限承诺 |

模型必须用真实 discovery ID，不接受伪造的 gpt-image/whisper 模型别名。
已有 Pi/Max provider 与默认型号不会因为添加接口被自动切换。

## Token 计数不是整份生成请求的精确价格

静态协议参考是 Gemini CLI 的 Code Assist converter；另外用本服务同一
OAuth 和 UA 对真实 `/v1internal:countTokens` 做了对照：`hello world`
返回 totalTokens=2，加入 systemInstruction/tools 后仍为 2。

因此 handler 不会把这些字段吞掉再声称计数完整：

- 接受原生 `contents`，以及仅有 model/contents 的 generateContentRequest。
- request body 的 model（若提供）须与 URL 中的型号一致。
- 拒绝 tools、systemInstruction 等无法可靠计入的字段。
- 返回上游真实 totalTokens，附 `X-Agy-Count-Scope: contents-only`。
- 上游遗漏/非法计数、错误、传输中断均报错，不补 totalTokens=0。

这个限制也写在 `/capabilities`；不能据它精确估算工具 schemas、系统提示、
缓存折扣或订阅费用。

## Responses：无状态，不伪装 OpenAI 服务端存储

只实现完整历史重放的文本/多模态输入与函数工具子集。system/instructions
和用户项目规则不改写，使用与 Chat 相同的真实生成后端；不是把 OpenAI
Responses JSON 直接发给 Google。

原生 model parts 包含工具签名及其位置，Responses 输出通过网关自己的
AES-GCM encrypted_content 保存这些 opaque replay 数据，使用独立用途
派生的代理 key 与随机 nonce。它不是 OpenAI 生成的 blob，也不意味着
解密 Google 的隐藏思考；Google 没有返回的内容不会凭空出现。

需要回放的请求应发送 `include: ["reasoning.encrypted_content"]`，下一轮
须传回完整 output items。网关校验原生模型、函数名、args 与
visible content 一致后恢复 parts；不依赖跨用户全局猜测缓存，不制造
thoughtSignature。代理 key 轮换会让旧 blob 失效；换 Google 账号后也
不保证旧签名可继续使用，应开启新会话。

- 显式 store:true、previous_response_id、output item references、hosted
  tools、WebSocket、检索/删除/取消已存储 response 等未实现语义须报错。
- SSE 发出实际文本/思考摘要/函数调用增量及相应生命周期，只有真实完成
  才结束成功；缺原生终止或中途失败不会补 completed / DONE。
- 思考摘要是上游返回的可见文本，不是模型完整内部推理。

客户端仍须正确保留 Responses reasoning item 的 encrypted_content。
这使现成 Responses 客户端有明确的回放载体，不等于旧版 Pi 的 Chat
provider 丢 extra_content 问题自动消失；新 provider 的实际接线与工具
回放还须单独验收。

## 图片、视频和音频

### 图片生成与编辑

`model` 必须是实际 `gemini-…-image…` 图像型号。请求使用 image_gen lane、
原生 responseModalities TEXT/IMAGE，不模拟生图成功。

- generations：JSON，prompt、n=1，返回真实 b64_json 与 mime_type；不提供
  临时公网 URL。size 只接受明确映射的正方形 1K/2K/4K，或单独 aspect_ratio。
- edits：multipart `image` / `image[]`、prompt，最多 4 张 PNG/JPEG/WebP；
  filename 只作格式提示，不作服务器路径。mask、未知编辑约束不静默忽略。
- 上游未返回图片、安全拒绝、截断或非法媒体都会报错，不把文字当作图片。
- 没有 `/videos` 后台生视频服务；视频输入理解和视频生成不是同一种能力。

Chat 的 user 图片/视频/audio 输入仍是 inline base64，不下载远程 URL。
Chat 新增图片工具结果：转换为 functionResponse.parts 的 inlineData，
文本中的 image 标号与附件顺序对应。音频/视频工具结果仍不默认猜测转换，
需要时使用原生 Gemini 字段；Chat 生成媒体输出也不冒充标准文字内容。

### 文件音频转写/翻译

multipart `file`，必须明确指定可用 Gemini 文本型号；不是 Whisper 专用
模型，也没有另行调用收费的外部语音服务。

- 接受与扩展名、Content-Type、容器签名相符的 WAV/MP3/M4A/MP4/OGG/WebM/
  FLAC；这不是完整 codec 解码验证，实际解码由上游负责。
- language 是可选的两字母语言提示，prompt 作为词汇/上下文 hint；不会
  把未验证的转写当作带时间戳/置信度/说话人分离的结果。
- response_format 只支持 json `{text:…}` 或 text，不虚构 verbose_json、
  SRT/VTT、timestamps、diarization、logprobs 或流式分段。
- translations 的目标为英文；原生生成的 thought 文本不混进转写正文。
- 不实现 `/audio/speech` 或实时 Bidi：当前订阅模型目录没有可验证的 TTS/
  realtime 后端，不能仅靠一个 URL 宣称支持。

### 大小与资源

请求总上限由 `max-body-bytes` 控制，默认 64 MiB JSON。multipart 另有
每文件 20 MiB、总内容 32 MiB、字段 64 KiB 和数量限制，上传在内存有界
处理，不把用户媒体临时落盘。base64 会膨胀，请不要将 JSON 上限当成
原始视频大小上限。upstream media response 和 replay/event 同样有界。v0.4.1 将等待上游响应头
的默认上限从 45 秒改为 120 秒，NixOS 用 upstreamHeaderTimeoutSeconds，
CLI 用 `--upstream-header-timeout`（1s–10m）；超时仍是失败，不自动重试。

## 明确不支持的上游能力

授权后，对已知的下列入口返回 501，不成功造一个对象：

- Files upload/storage、Google cachedContents、batch jobs/operations；
- embedContent/batchEmbedContents、OpenAI embeddings；
- 语音合成、生视频异步任务、实时音视频；
- Responses 服务端存储、previous_response_id、WebSocket 与 hosted tools。

这些功能需要真正提供相应接口的独立上游及其凭据/存储政策。网关不自动
开启 GCP 产品、花费 credits、购买套餐或把 Antigravity OAuth 转发到
客户端指定的任意 URL。未知接口仍可能返回 404。

## 传输错误的诊断版本

v0.4.1 在线上会把所有 `Client.Do` error 合成同一条通用 502，不能据此
区分等待响应头超时、DNS、TLS、断连或客户端取消。v0.4.2 源码增加
`diagnostic_id`、`failure_class`、`upstream_phase`、`elapsed_ms` 扩展字段，
与无 URL/prompt/token 的 httptrace 日志关联；HTTP status 仍是 502，
不改自动重放策略。分类日志使用 journal priority 前缀，适配 gizmo
只持久化 notice/warning 的设置。

**v0.4.2 已于 2026-11-19 随完整配置重启生效**，真实 API 和诊断日志
验收见下一节。这不声称已经修复偶发网络失败；仍需按实际失败类别决定
是否调整超时/连接策略，不能先猜 HTTP/2 或清冷却。历史证据与误判见
[传输 502 排查](incidents.md#agy-transport-generic-502)。

## 2026-11-19 · 最新完整配置重启生效与验收

按用户要求，不再只替换 AGY runtime overlay，改为部署 gizmo 的完整最新
声明。同步到 main `0c23a3a9`，在 r6s 以 max-jobs=1 / cores=2 构建，并
通过 root SSH 将自己构建的闭包传到 gizmo；没有在 gizmo 上编译。
传输只对此次闭包使用 `--no-check-sigs`，未修改全局信任或签名检查设置。

完整目标为
`/nix/store/0zh2qqg3babgpdklnnp45jwjqjilgrmj-nixos-system-gizmo-26.05.20261113.f1e5c35`。
与 `/run/current-system` 相比，包级差异是 AGY 0.2.1 → 0.4.2、CLIProxy
8.0.74 → 8.0.77 和 tzdata 2026f；其中 AGY 的旧闭包版本不等于当前
runtime overlay 实际运行的 0.4.1。与原启动默认 `dk69ic1k…` 相比，
包级差异仅 AGY 0.4.1 → 0.4.2。

15:08 HKT 先执行 `switch-to-configuration boot`，默认变为 **117**，
未先执行 system switch。当时机器自 11 月 6 日启动仍加载 **6.18.57**，
完整目标是 **6.18.63**；这是已经存在的未重启漂移，不是本次新改了内核
输入。gizmo 是出口节点，因此先等待重启确认，不继续混用新用户态与旧内核。

写 boot 时 `/run/current-system` 仍为 `kxnnv8p7…`；AGY / nginx / CLIProxy
PID 是 159427 / 3982168 / 165944，healthz 正常，三项临时 runtime
覆盖均保留，以免在真正启动新版前撤掉正在工作的 API。
OAuth 和客户端 key 均未轮换、未备份或分发；未激活任何 home。

24 台系统配置的 drvPath 求值全部通过。旧默认代 **116** 与已知可启动的
**98**（`mj8cgahc…`，内核 6.18.57）仍在 extlinux，已核对后者的内核
文件保留。

随后用户明确批准，15:46 HKT 发出 reboot，约 **67.1 秒**后 SSH 以新
boot ID 恢复。加载内核为 **6.18.63**，`/run/booted-system`、
`/run/current-system`、启动默认均为上述 `0zh2qqg3…`。AGY PID **763**，
实际 ExecStart 为 `/nix/store/354y5g34bcl9wf48hfc5d6brw7wgb02l-agy-proxy-0.4.2/bin/agy-proxy`；
nginx / CLIProxy PID 为 **1014 / 949**，后者实际运行 **8.0.77**。
三项旧 runtime override 随重启清空，不再依赖临时补丁。AGY header wait
仍为 120 秒，没有新增 generation 重试。

重启后经真实 HTTPS 验收，输出只保留状态/耗时/fixture 是否匹配，不保存
凭据、签名或密文内容：

| 验收 | 结果 |
| --- | --- |
| capabilities 与 CLIProxy models | 200；兼容层启用，Sol/Astra 两项在目录，Vertex 两组退役前缀为零 |
| contents-only countTokens | 200，hello world=2，scope header 正确，1.61 秒 |
| 原生 Flash High 生成 | 200，指定 fixture 正确，5.15 秒 |
| Hydrogen High Chat 工具第一轮 / 第二轮 | 两轮 200，6.12 / 3.59 秒，完整 native metadata 回放，返回固定 stub 结果 |
| AGY Responses | 200，指定 fixture 与 encrypted native carrier 存在，4.69 秒 |
| CLIProxy GPT 6.2 Sol Responses | 200，指定 fixture 与真实返回模型 ID 正确，4.45 秒 |
| tank 的 Max 共享 forwarder | `/var/lib/maxx/vm/max.sock` 的 `/llm` 含 14 个 AGY 模型；Hydrogen High SSE 的 fixture / DONE 均正确 |

Max 验收实际使用正在监听的共享 socket，不是已经闲置的历史 VM 3 socket；
后者仅 connect 失败，未发出模型调用。没有重启 Max、修改用户默认模型
或给 VM 配真实 key。

另外仅对 loopback countTokens 发起一次**合成、非生成**取消探针：在
40ms 主动断开客户端后，真实 AGY 日志记录 `class=client_canceled`、
`phase=response_headers`、`elapsed_ms=39`、`protocol=h2`、
`request_written=true`、`replayed=false` 及关联 ID，journal priority 为 **5**，
证明 notice-only 的日志策略可以保留诊断。这是受控取消，**不是复现原来的
自然 502，也不证明其根因已修复**。客户端已经断开，因此此项只验收日志；
502 JSON 扩展字段仍以离线故障注入测试为证。

最终系统 `running`，失败系统单元为零，AGY / nginx / CLIProxy /
Tailscale / Rex login server 均 active，IPv4/IPv6 forwarding 开启。启动期间
Rex/SOPS 的短暂失败已自行恢复（Hank 用户 sops-nix Result=success）；
快速 SSH 探针曾留下空 cgroup 的 scope resources 记录，核对 No PIDs
left 后只清除了这些瞬时 scope 的 failed 状态，未重启或掩盖实际服务失败。

## 2026-11-18 · v0.4.1 上线与真实验收

实现提交 `f339a4cd`，实测 header wait 修复 `65406410`。在 r6s 以
max-jobs=1 / cores=2 构建，先启动 gizmo loopback 8320 的限时预检实例，
经 SSH 隧道验证，Google OAuth 始终留在 gizmo，未复制到测试端。

| 真实调用 | 结果 |
| --- | --- |
| 新号 Flash High 生成 | 200，验证文本正确 |
| contents-only countTokens | 200，hello world=2，scope header 正确 |
| Responses JSON + encrypted_content | 200，输出文本正确，真实 AES-GCM blob |
| Responses SSE 函数调用 + encrypted blob 第二轮回放 | 两轮 200，增量/生命周期正确，最终文本正确 |
| Chat 图片输入（合成红色 PNG） | 200，正确辨认红色 |
| Chat 视频输入（合成 2 秒红色 MP4） | 200，正确辨认颜色，约 84.55 秒 |
| Chat WAV 音频输入（本机合成语音） | 200，识别验证语句 |
| multipart 音频转写 | 200，识别 verification code，约 81.92 秒 |
| multipart 音频翻译 | 200，返回正确英文验证语句 |
| 图片生成 | 200，返回 443502 bytes 的实际 JPEG，主色为红色 |
| 图片编辑（红方块改蓝） | 200，返回 204142 bytes JPEG，解码后的主色已变蓝 |
| 原生 functionResponse.parts 图片工具结果 | 两轮 200，正确辨认工具返回图片的红色 |
| 真实 Pi + 本网关 Responses + 完整仓库上下文 | 两轮 HTTP 成功，1 次实际 read，约 121.46 秒，签名 blob 完成回放 |

Pi 的临时 Responses 验收禁用了客户端的 prompt-cache hint / long-retention
参数（这个上游不提供对应的显式缓存语义），并使用已验证的简短真实
系统提示词；没有更改用户的持久 provider。测试 compatibility 是：
`supportsDeveloperRole=false`、`supportsStrictMode=false`、
`promptCacheKeyMode="disabled"`、`supportsLongCacheRetention=false`。

45 秒旧 timeout 曾让合法视频和转写请求变成 transport 502；不是模型
拒绝。改成有界 120 秒后两项均通过。没有给 generation 加自动重试。
测试素材均为本机合成 PNG、MP4、TTS WAV，不含用户图片/声音；结果日志
不保存原始请求、签名 blob、token 或音频。

生产只替换 `agy-proxy.service` 的 runtime ExecStart drop-in，PID `159427`，
版本 **0.4.1**；nginx / CLIProxy 的 PID 保持不变。现有 HTTPS 的
`/agy/v1/` 和 `/agy/v1beta/` 无需重启 nginx 即覆盖新路径。
实际 HTTPS Responses 验收 200 / 指定文本正确 / encrypted carrier 存在；
Files、embeddings、audio/speech 的已知未实现接口实测均为 501。
预检实例、8320 监听、SSH 隧道与回退 timer 均已清理。

运行系统仍是 `kxnnv8p7…`，加载内核仍 6.18.57；没有整套 switch 或重启。
完整声明已设为下次启动默认：
`/nix/store/5qj10w8iqh2g03ngfj2z1vjxlls2j4p2-nixos-system-gizmo-26.05.20261113.f1e5c35`。
当前服务 drop-in 引用该声明的新二进制与 120 秒参数，不是未提交手工代码。

## 验证

默认测试不联网、不读取实际 OAuth，不把语音/图片或 blob 打进日志：

```sh
cd pkgs/agy-proxy
go test -race ./...
go vet ./...
```

覆盖原生/Chat 回归、Responses 事件与签名密文防篡改、图片/音频 multipart、
错误/截断/取消、大小上限、认证、无自动 generation replay，以及 token
counter 不静默忽略系统/工具字段。真实媒体验收须使用合成测试素材，
并记录实际上游结果，而不是用一段伪装成 PNG/WAV 的字符串当作已验收。
