# CLIProxyAPI：HTTP 与 HTTPS 并存

Gizmo 提供两个入口，使用同一份调用密钥、模型和 OAuth 凭据：

| 入口 | 地址 | 用途 |
| --- | --- | --- |
| HTTP | `http://gizmo.inner.imdomestic.com:8317/v1` | 保留现有 pi、OpenCode 和服务端客户端配置 |
| HTTPS | `https://gizmo.inner.imdomestic.com/v1` | fx 等要求非 loopback 地址使用 TLS 的客户端 |

两个入口都只在 tailnet 内可达；HTTP 不重定向到 HTTPS。HTTPS 的 nginx 仅代理
`/v1/`，不转发 `/v0/management/` 等管理路径。调用使用 `cliproxy/api_key`，不是
`cliproxy/management_key`。原 HTTP 管理接口的权限边界不变。

## 实现与证书

`hosts/gizmo/cliproxy-https.nix` 由 `hosts/gizmo/host.nix` 显式加载：

- 复用本机 nginx，在自己的 MagicDNS 地址监听 TLS 443；上游仍是 CLIProxy 的
  Tailscale HTTP 地址，不是 `127.0.0.1:8317`。
- `my.tailscale.bindServices` 在启动前确认 DNS 答案属于本机 `tailscale0`，不回退到
  wildcard 监听。443 只在防火墙的 `tailscale0` 放行。
- 原生 `security.acme` 使用 Cloudflare DNS-01，复用本机已有的
  `ddns/cloudflare_token`，通过 SOPS template 提供 `CF_DNS_API_TOKEN`。
  token 不写进 Nix store。
- ACME 的查询使用 `1.1.1.1:53`，避免 MagicDNS 的 SOA 限制；参见
  [gaoji 的先例](incidents.md#gaoji-acme-inner-soa)。不新增公网 A/AAAA 记录，也不为
  签发开放公网端口。公开证书的透明度日志会记录该域名。
- nginx 等待签发，并在启动前验证证书链和域名；ACME 的临时自签证书不能作为
  已上线的 HTTPS 入口。原生 nginx 模块为该证书注册自动 reload，ACME timer 负责续期。
- 关闭响应和请求缓冲，读取/发送超时为一小时，支持 SSE 和 WebSocket。
  nginx 现有的 50 MiB 请求体限制保留。

## fx

fx 的自定义 provider 使用 `openai-chat-completions`，`base_url` 填
`https://gizmo.inner.imdomestic.com/v1`，Bearer 认证从 `CLIPROXY_API_KEY` 环境变量取。
不再需要 SSH 隧道。模型 ID 和上下文预算见 `lib/cliproxy-models.nix`。

本机已有 SOPS 调用密钥时，可以在当前 shell 设置：

```sh
export CLIPROXY_API_KEY="$(cat ~/.config/sops-nix/secrets/cliproxy/api_key)"
fx status --json
fx ask --no-save "只回复 OK"
```

fx 自定义连接目前只支持 Chat Completions，不透传 provider-specific reasoning
controls；[官方说明](https://fx.sh/docs/configure-fx/custom-model-connections.md)。

## 检查与部署

```sh
nix eval --raw .#nixosConfigurations.gizmo.config.system.build.toplevel.drvPath
just check-sops gizmo
just lint
ssh hank@gizmo 'systemctl status nginx acme-order-renew-gizmo.inner.imdomestic.com --no-pager'
ssh hank@gizmo 'systemctl list-timers acme-renew-gizmo.inner.imdomestic.com.timer --no-pager'
```

端到端验收须使用正常的 TLS 验证，不能以 `curl -k` 或 ACME ensure 单元成功代替
正式签发成功。检查 HTTP/HTTPS `/v1/models`、无密钥拒绝、管理路径 404、
Chat Completions/Responses 流式输出，以及公网/LAN 地址上不存在 API 监听。

Gizmo 的系统在 registry 指定的 r6s 上构建，目标机只接收闭包；不要在 gizmo 上
编译。网络或防火墙变更先测试激活，保留原运行代和回退路径；参见 `AGENTS.md`。

## 2026-11-05 上线验收

实现提交 `38a868f2`。24 个系统配置求值、`just lint`、gizmo 的 SOPS 声明校验和
生成单元的 `systemd-analyze verify` 通过。r6s 使用 `max-jobs=1`、`cores=2` 构建；
闭包同时同步仓库已有的 CLIProxy 8.0.53 → 8.0.55，内核仍为同一个 Linux 7.3。

先测试激活，再将已验收的代设为 boot 默认，未重启：运行代和系统 profile 均为
`/nix/store/b4cf392757pmdns5flr1cj2nbnk1lksd-nixos-system-gizmo-26.05.20261020.cd4ea8d`。
临时 20 分钟回退 timer 已取消，nginx/cliproxy/tailscaled 正常，failed units 为 0。

HTTP/HTTPS 返回相同的 74 个模型；无密钥访问 HTTPS API 为 401，HTTPS 管理路径
为 404。HTTPS Chat Completions、HTTPS/HTTP Responses 均返回完整 SSE `OK`；
认证 WebSocket 升级为 101，无密钥升级为 401。fx 0.0.16 经 HTTPS 实际调用
`read_file` 并返回临时探针文件内容，不是只验证模型目录。

证书由 Let's Encrypt YE2 签发，域名校验和正常系统信任链验证通过，到期时间为
2027-02-03 10:27:48 UTC。443、8317、8318 只监听本机 Tailscale IPv4；从本机 Mac
到 gizmo LAN IPv4 和公网 IPv6 的 443 均不可达。

启动顺序的预检陷阱见 [DNS-01 与 nginx 原生排序](incidents.md#cliproxy-https-dns01-ordering)。
