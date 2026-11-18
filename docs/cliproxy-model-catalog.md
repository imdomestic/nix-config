# CLIProxy 的模型目录补充

## 目录来源

`hosts/gizmo/system.nix` 通过原生 `services.cliproxy.settings.models.catalog`
加载 `lib/cliproxy-catalog.nix` 生成的完整目录。它以
`router-for-me/models` 的固定提交为基线，URL 与 SHA-256 在 helper 中；
没有复制一份原始 JSON 到仓库，也不把任何 OAuth 或调用密钥放进目录。
选择完整官方快照而非 8.0.69 的嵌入表，是因为此次官方目录还多了三条
AI Studio Gemini 4 型号；只从嵌入表开始合并会把它们丢掉。

自定义目录是**整体替换**，不是增量补丁。helper 保留基线的全部 provider
分组，只在指定分组里按 ID 合并补充定义：已有 ID 的未覆盖字段保留，重复
ID 先移除再写入。不能把一个只含新增三个型号的 JSON 当完整目录使用。

显式指定本地目录后，CLIProxy 不再自动回退到官方 URL；周期刷新只会重读
同一个生成文件。因此升级官方目录快照时，要一起更新 helper 的固定提交
和文件 SHA-256，并检查其他 provider 没有丢失，不能只更新这三条补充记录。
更新 CLIProxy 软件包不会自动更新这个固定快照。

## Hydrogen 的四个预设

`lib/antigravity-hydrogen.nix` 是服务端、Pi 和 Max 共用的型号数据。它定义
`gemini-4-hydrogen-{low,medium,high,xhigh}` 四个真实 Google ID，不使用
`oauth-model-alias` 将它们映射到 XHigh。账号能否使用某条仍由 Google 的
账号目录与验证状态决定；补充静态定义不会给其他账号增加权限。

Google 原始目录声明四条都有 1,048,576 上下文、262,144 输出上限，以及
文本、图片、音频和视频输入。每条在 CLIProxy 中只声明与预设匹配的
thinking level，不猜数字 thinking budget；依据与此前误判见
`docs/incidents.md#antigravity-hydrogen-effort`。

Hank 的 Pi 将四条作为独立型号显示，每条只开放对应档位；仍只声明文本和
图片输入，保留 65,536 的客户端输出预算。四条共用同一公开 Hydrogen 价格
估算，而非 Antigravity 订阅账单。

当次 Max 的四条共用已有 Vertex Hydrogen 的 `googleHydrogen` 配置（两组
Vertex 路由后来已退役，见 [AGY 迁移](agy-chat-completions.md)），包括
262,144 会话预算、视频开关和价格，不另设输出上限。默认聊天、任务、
caption、dreamer 型号均不改变。切换预设通过 `/model` 选择真实 ID，
而不是指望 `/effort` 改变型号 ID。

## 生效与验收

只改文件不会立即生效。之后获准部署时，要让 gizmo 加载新目录、激活
Hank 的 home，以及让 Max 加载新配置；无需修改或重新编译 CLIProxy Go
代码。检查公开 `/v1/models` 有四条、账号目录允许四条，并分别进行独立
短请求确认真实路由。遇到 Google 账号验证或额度拒绝，不清除限制来做验收。

2026-11-15 最初按用户要求仅修改配置并提交，未构建、运行 Nix 检查或部署。

## 2026-11-15 · 上线验收

用户随后授权部署，配置提交为 `5efc1f22`。先检查缓存与缺失 derivation，
只生成了 15 个配置/数据产物，未编译软件源码、未跑 `nix flake check`。

- gizmo 在 r6s 上生成配置并接收闭包；只安装新的 SOPS manifest、重启
  CLIProxy。该服务 unit 与旧代完全相同，不留 runtime override。公开目录
  有四个真实预设，四档独立短请求均为 200 / OK。完整新系统
  `/nix/store/l3fhshkh7hpjcxz5gzha6z2f7681hbng-nixos-system-gizmo-26.05.20261113.f1e5c35`
  已设为下次启动；运行系统仍是 `17kx445…`，本次未重启或激活新内核。
- tank 的 Max 原生配置已持久激活，运行和启动默认均为
  `/nix/store/i199n7sp8wsags62a9m5037qj6g2pr1d-nixos-system-tank-26.05.20261113.f1e5c35`。
  原有 8 台 VM 的 PID 未改变，全部 active VM 的 `forward.config` 已指向
  新配置并包含四条 Hydrogen。使用 Max 调用密钥的 Low 短请求也返回 OK。
- praxic / hank 的完整 home 仍有 Node/PostgreSQL 等源码构建需求，所以
  **没有激活整套 Home Manager**。只把 Nix 生成的 `models.json` 原子链接到
  `~/.pi/agent/models.json`，新增 GC root
  `~/.local/state/home-manager/gcroots/hydrogen-models`；原模型文件另保存在
  `hydrogen-models-previous` root。当前源是
  `/nix/store/wvi5400cvfp4bflmmznq5r2q5lapcyam-hm_.piagentmodels.json`，Medium
  和 XHigh 的 Pi 实际请求均返回 OK。以后完整 home 激活追上这个配置后，
  可清理这两个额外 GC root。

Max 激活首次因短暂 root logind 对象退出而中断，服务恢复后在保持 root SSH
会话期间重跑激活成功；临时回退计时器均已撤销，没有失败系统 unit。gizmo
验收期间旧回退计时器曾到期，重新加载新 manifest 并撤销计时器后再次确认
四条模型和 Pi 请求正常；不把那次回退误判为上游型号消失。
