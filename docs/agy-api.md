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
