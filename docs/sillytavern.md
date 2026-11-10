# SillyTavern · seraph

## 访问与登录

入口：**http://seraph.inner.imdomestic.com:8000/**，需要已连接 Tailnet。
浏览器的 HTTP 认证用户名是 `linwhite`。密码是独立生成的随机密码，取出方式：

```sh
ssh linwhite@seraph.inner.imdomestic.com 'sudo cat /run/secrets/sillytavern/password'
```

密码加密保存在 `secrets/hosts/seraph.yaml`，不与任何模型 API Key 共用。
HTTP 流量在 Tailnet 的 WireGuard 隧道内传输；没有启用 Funnel、公网入口或
自签名 HTTPS。不要在公网反代这个端口。浏览器仍将 HTTP 视为非安全上下文：
聊天和流式输出已验证，录音等要求 HTTPS 的浏览器功能不在本次部署范围内。

## 模型连接

打开顶部 **API Connections** 面板，在 **Connection Profile** 下拉框切换。
首次安装默认选择本机的 **Bonsai Hikari**，不需要填写 API Key。
已完成首次引导，Persona 名为 `linwhite`，并开启自动连接上次服务器。

| 连接 | 模型 / 用途 |
| --- | --- |
| Bonsai Hikari / Bonsai 2 | seraph 本机的两个 27B 模型，174080 上下文；互斥加载 |
| Qwen3.8 Swift / Aligned | taipan 的两个 27B 模型，262144 上下文；主机需启动到 NixOS |
| CLIProxy · 全部模型 | 动态读取 CLIProxy 的 `/v1/models`，过滤 Rewind；默认 Gemini 3.8 Flash High |
| CLIProxy · GPT / Claude / Vertex / DeepSeek | 同一网关的常用模型快捷连接；仍可在模型下拉框选择其他模型 |
| Qwen3.5 4B | h610 的 llama.cpp，当前运行窗口为 32768 |
| Ollama · Qwen3 8B / Gemma 4 E4B | tank 的两个小模型，使用保守的 4096 客户端窗口 |

CLIProxy 的新模型会随重新连接 / 刷新模型列表出现，不需要修改 Nix 列出每个模型。
网关目录也包含 `gpt-image-*`、Imagen 等生图模型；它们**不是 Chat Completion
对话模型**，不能当成聊天模型选择。Clef 的 `/v1/systemone` 决策接口也不是聊天
接口，因此没有创建一个看似可用但实际上不兼容的连接。

**Rewind 不接入本实例。** 它是[有使用条件的提供商](rewind.md#usage-conditions)，
在共享模型资料中标记 `conditional = true`。本实例不保留 Rewind 连接或预设，
模型目录过滤 `rewind/`，手填的 Rewind 生成请求也会在调用上游之前被拒绝。
其他客户端已有的显式 Rewind 配置不变；不要把共享 CLIProxy Key 当成已经满足
该提供商使用条件的证明。

云端快捷连接默认采用 131072 或 262144 的保守客户端上下文预算，回复预算为
4096（GPT、Argon 为 8192）；这不是对上游最大能力的声明。按需在
SillyTavern 的 Chat Completion 预设里修改，不会改变模型服务器本身的容量。
本机的两个 Bonsai 预设分别保留 Hikari 的 medium / Bonsai 2 的 high 思考设置。

**真实模型 Key 不进入 SillyTavern 的 secret store。** Bonsai 与 CLIProxy
经过 seraph 上仅监听 `127.0.0.1:8002` 的 nginx 固定路由，由 SOPS 管理的
私有 header 片段注入各自的 Key。SillyTavern 的所有连接仅保存 `not-required`
占位 Secret，切换顺序或多个浏览器的 active secret 互相影响也不会串用真实 Key。
界面里的 `127.0.0.1` 是 **seraph 服务端**发起模型请求的地址，不是访问者电脑。

原因是 1.18.0 的 Connection Manager 在切换 Secret 之前就改变 URL 并检查
`/models`；只保存不同 Secret ID 仍不够隔离凭据。固定上游路由避免了这个时序
问题，不需要修改 SillyTavern 的前端，也不暴露 CLIProxy 管理接口。

## 配置、状态与维护

- 原生 NixOS 服务与 Tailnet 反代：`system/modules/sillytavern/default.nix`。
- 地址来源：`flake/placements.nix`；Bonsai 参数：`lib/bonsai-models.nix`。
- 幂等初始化：`system/modules/sillytavern/bootstrap.py`，通过官方
  HTTP API 创建连接和预设，不直接覆写用户的 `settings.json`。
- 持久状态：`/var/lib/SillyTavern/`，聊天、角色、世界书、预设与 Key 都在这里。
  备份整个目录时按敏感数据处理，不要提交到 Git。
- Nix 只管理服务器安全配置、固定上游的模型 Key 和初始化的连接。后续重启 /
  部署不得重置用户选择、改过的预设或聊天记录。重新运行 bootstrap 只补建管理的
  连接 / 预设并保留已有编辑，不重置界面。
- 升级 SillyTavern 前需要复核 bootstrap 的 REST schema 及排除规则补丁；当前
  固定验证 1.18.0。
- SillyTavern 仅监听 `127.0.0.1:8001`；nginx 仅监听本机 MagicDNS 对应的
  Tailnet 地址 `:8000`，另有独立 nftables 接口守卫。保留 Basic Auth、CSRF、
  Host whitelist 和服务端私网请求白名单。

日常检查：

```sh
systemctl status sillytavern sillytavern-bootstrap nginx
sudo journalctl -u sillytavern -u sillytavern-bootstrap -u nginx --since today
```

重建是**系统**部署（先按 `AGENTS.md` 做 freshness check）：

```sh
just switch seraph
```

不用 Home Manager activation。补建缺少的管理连接 / 预设可运行：

```sh
sudo systemctl restart sillytavern-bootstrap
```

修改登录密码应使用 `sops set --value-stdin` 更新加密字段，再从新鲜 checkout
部署系统；不要只手改运行时 YAML。密码更新会重启 SillyTavern，保留用户数据。

bootstrap 单元测试及真实端口的隔离防火墙回归：

```sh
source=$(nix build --no-link --print-out-paths .#nixosConfigurations.seraph.pkgs.sillytavern.src)
python3 scripts/test-sillytavern-bootstrap.py --source "$source"
sudo unshare -n python3 scripts/test-tailscale-web.py 8000 8080
package=$(nix build --no-link --print-out-paths .#nixosConfigurations.seraph.config.services.sillytavern.package)
node scripts/test-sillytavern-exclusions.mjs "$package/lib/node_modules/sillytavern"
```

## 2026-11-10 · 上线验收 {#acceptance}

SillyTavern 1.18.0 已部署到 seraph，当前运行系统为
`/nix/store/85gp4v0bvkhknp68pvj1zqjawa77mjlp-nixos-system-seraph-26.05.20261105.c56a87d`。
没有更新内核或 NVIDIA 驱动，没有重启机器，也没有激活 Home Manager。

- 24 个 NixOS / Darwin 配置求值及 `just lint` 通过；bootstrap 23 项测试、
  安装包排除规则测试、真实端口的 15 项隔离 IPv4/IPv6 防火墙检查通过。
- 从 gizmo 的真实 Tailnet 客户端访问入口，未认证返回 401；内部 8001 / 8002
  不可达。同一 LAN 上访问 seraph 的 `10.1.2.194:8000` 也不可达。
- 合法登录可打开页面；缺少 CSRF 的 POST 与非法 Host 均返回 403。
- 12 个连接保留，Rewind 连接、未使用的预设及管理记录已移除。验收时 CLIProxy
  目录 79 个 ID 中的 8 个 `rewind/` 被过滤，其他 71 个保持不变。手填 Rewind
  在 Custom / OpenAI / Claude 请求路径均立即返回 `model_not_allowed` / 403。
- 两个 Bonsai、Gemini 3.8 Flash High、GPT 6.1 Sol、Claude Opus 4.6 Thinking、
  Vertex Gemini 4 Argon、DeepSeek V4.1 Flash、h610 Qwen3.5 4B、tank Qwen3 8B /
  Gemma 4 E4B 的小请求均返回文本和完整的流式终止帧。这是连通性验收，
  **不是**所有目录 ID 的能力、长上下文或性能保证。
- Chromium 实际完成首次引导、连接切换与模型目录过滤；新页面自动连接本机
  Hikari，聊天框发送中文请求后得到“部署验收通过”，无页面脚本错误。
- 重启 bootstrap 后，用户 settings 文件逐字节不变，保留 Persona、自动连接、
  选中的 Hikari 及其余偏好。真实模型 Key 仍仅在 nginx 私有 SOPS header 中，
  SillyTavern 服务用户不能读取，secret store 中只有 `not-required`。
- taipan 的 NixOS 节点离线，Windows 节点在线；本次不重启那台机器或切换系统。
  两个 Qwen3.8 连接已经配置，但尚不能做在线生成验收。

原始流式请求、浏览器截图与排除规则记录保存在 seraph 的
`/var/lib/sillytavern-validation/20261110/`，按私有运维记录处理。
