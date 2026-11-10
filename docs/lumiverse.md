# Lumiverse · seraph

## 两个独立入口

| 应用 | Tailnet 地址 | 登录 |
| --- | --- | --- |
| SillyTavern + Charites | http://seraph.inner.imdomestic.com:8000/ | 原来的 HTTP 认证，用户名 `linwhite` |
| Lumiverse | **http://seraph.inner.imdomestic.com:7861/** | 页内登录，用户名 `linwhite`，独立密码 |

Lumiverse 初始密码：

```sh
tailscale ssh linwhite@seraph.inner.imdomestic.com 'sudo cat /run/secrets/lumiverse/password'
```

密码加密保存在 `secrets/hosts/seraph.yaml`。首次启动通过官方 `OWNER_PASSWORD`
环境入口创建 owner；应用把密码哈希存入自己的数据目录。之后修改用户密码用
Lumiverse 的原生账户功能，**修改 SOPS 的初始密码不会覆盖已经存在的账户密码**。
初始化服务成功后会留下 `.nix-bootstrap-complete` 标记，此后重启 / 部署不再用
初始密码自动登录。**你可以直接在 Settings → Account → Change Password 中
填写当前密码、新密码及确认密码（8–128 字符），无需修改 Nix 或 SOPS。**
其他设备的登录会话会被注销，需要用新密码重新登录；当前会话保留。

`/run/secrets/lumiverse/password` 此后仍是部署时的初始密码，不会变成网页中
设置的新密码。应用在修改密码时更新数据库，不把新密码交回 Nix。
`owner.credentials` 也是初始建号文件，不应当作当前登录密码的权威副本；
现有数据库在重启时不会被它重置。备份应包含数据库，不要靠旧建号文件重建账户。

两边不共享数据库、会话、主题、角色或聊天目录。**没有自动迁移 ST 数据**，
Lumiverse 容器没有挂载 ST 目录。保留现有 ST，先在 Lumiverse 的临时聊天里
试用；将来需要导入时，应使用一致的 ST 备份快照作为只读来源，而不是让两个
应用同时写同一份数据。Charites 是 ST 插件，不能装进 Lumiverse。

## 模型与使用

已创建 7 个原生连接：Bonsai Hikari、Bonsai 2、CLIProxy、Qwen3.8 Swift、
Qwen3.8 Aligned、h610 Qwen3.5 4B、tank Ollama。默认选中本机 Hikari。

- 在侧栏 **Connect / Connections** 管理连接与模型。
- CLIProxy 连接默认 Gemini 3.8 Flash High，可读取上游模型目录并选 GPT、Claude、
  Gemini、DeepSeek / MiMo 等；不是仅能用默认模型。
- Ollama 默认 `qwen3:8b`，同一连接也能选 `gemma4:e4b-it-q4_K_M`。
- 首页 **Temporary chat → No preset** 可以直接测试模型；手机上临时聊天按钮
  只显示图标。手机默认 Enter 换行，发送请点发送按钮。
- Qwen3.8 所在的 taipan 当前 NixOS 离线，因此连接只完成预设；本次不切换其
  Windows / NixOS，也不重启那台机器。
- **Rewind 不接入。** 继承用户对有使用条件提供商的要求，模型目录过滤
  `rewind/`，注册的对话提供商在普通与流式生成前均拒绝该前缀。
- CLIProxy 目录中还有生图等非聊天模型，不应选作普通对话模型；没有在此次部署
  中配置生图、TTS、语音识别或其他需要独立适配的功能。

两个前端复用相同的推理服务器。Bonsai 的两个模型共享一张 GPU，切换模型会
互斥装载；同时使用两个前端不会获得两份独立的显存或推理容量。

真实模型 Key 不进入 Lumiverse。CLIProxy 和 Bonsai 请求经已有的
`127.0.0.1:8002` 固定 nginx 路由注入凭据；Lumiverse 仅保存无权限占位 Key。
界面中的 localhost 是 **seraph 服务端**，不是访问浏览器所在的电脑。

## 部署与状态

- `system/modules/lumiverse/default.nix`：原生 NixOS OCI 容器、SOPS、nginx 与
  systemd 初始化；`flake/placements.nix` 管理对外端口。
- 官方镜像：`ghcr.io/prolix-oc/lumiverse`，amd64 digest
  `sha256:3c6c0a94e3cabbcda04dcab1de3962a11b90440ec22d003e1dc8cb92c00be8f6`。
- 版本 1.2.5、Bun 1.4.4，源码 revision
  `45f8db563e1c314ed2aab227613b28eb5ea1084e`，与镜像标签及实际文件哈希核对一致。
- 容器用独立系统用户 UID/GID 976，根文件系统只读、删除全部 capabilities、
  no-new-privileges；最多 4 GiB 内存、4 CPU，无 GPU 或宿主设备映射。
- `/var/lib/lumiverse`：独立的数据库、密钥、用户文件与扩展，目录 0700。
  `lumiverse.identity` 是加密身份，**必须连同数据库一起备份**，不能丢弃。
- `bootstrap.py` 通过原生登录和 REST API 创建连接；成功后由 systemd 启动脚本
  写入 `/var/lib/lumiverse/.nix-bootstrap-complete`，以后自动跳过。手动运行 helper
  也不覆盖用户编辑，不恢复用户主动删除的连接或重置默认选择。它只初始化
  连接，不修改 Loom 提示词预设，不访问模型上游。
- `model-policy.ts` 与 `model-policy.patch`：只读挂载到固定 revision，保持本实例
  的条件提供商排除规则；升级镜像时须同时核对源码 revision 并重跑测试。
- 不运行交互式 updater / runner。界面的 runner 更新、切分支、重启等操作不用于
  本部署；更新通过 Nix 配置和固定镜像 digest 管理。

网络边界：Bun 只监听 `127.0.0.1:7860`；nginx 只监听 Tailnet 地址 `:7861`，
独立 nftables 守卫进一步限制接口。没有 Funnel、公网或 LAN 入口。保留应用
原生认证，关闭任意 Origin 信任，仅信任声明的 Origin 与 loopback 反代。
HTTP 由 Tailnet 隧道加密，但浏览器仍视其为非安全上下文；基础登录、聊天、
WebSocket 已验收，Push / 麦克风等依赖安全上下文的功能不在本次范围内。

维护命令：

```sh
systemctl status podman-lumiverse lumiverse-bootstrap nginx
```

初始化完成后，`lumiverse-bootstrap` 被 condition 跳过是正常状态，不代表服务
故障。不要为重跑初始化而删除标记：用户可能已经改了密码。后续添加连接优先
使用网页；确需重新运行 helper 时，用安全的临时凭据文件提供当前密码，不要
把密码写进命令行、Git 或日志。

日志和浏览器状态可能包含会话标识，不要直接公开日志。系统部署遵守
`AGENTS.md` 的 freshness check；Home Manager 不参与。

## 2026-11-10 · 验收 {#acceptance}

- 13 项 bootstrap 隔离测试通过；固定镜像 Bun 下 3 项提供商策略测试、52 项
  断言通过，包括全部 23 个注册提供商的非流式 / 流式拒绝及零网络请求。
- 登录页面可达，未认证 connections / settings / secrets API 均返回 401。
- gizmo 的真实 Tailnet 客户端可访问 7861，无法访问内部 7860；同一 LAN 上的
  `10.1.2.194:7861` 不可达。ST 的原有 8000 入口仍正常返回认证挑战。
- 7 个连接初始化成功，Bonsai / CLIProxy / h610 / Ollama 的模型列表正常，
  CLIProxy 返回 71 个非 Rewind ID（上游目录当时为 79 个）。
- 经 Lumiverse 原生生成 API 的 Hikari、Gemini 3.8 Flash High、GPT 6.1 Sol
  均收到实际回复；手填 Rewind 被本地策略拒绝，没有提交给模型上游。
- Chromium 桌面浏览器完成登录和中文临时聊天，WebSocket 流式输出成功；
  390×844 手机视口也完成实际发送并收到 `MOBILE_OK`，没有页面脚本错误或
  横向溢出。临时测试聊天返回首页后按应用设计删除。
- 重跑初始化前后的连接、默认连接及管理记录相同；没有改写 ST 的模型设置。

原始验收记录和截图：`/var/lib/lumiverse-validation/20261110/`。截图不是可恢复
备份；其中的浏览器测试会话应在验收后注销。
