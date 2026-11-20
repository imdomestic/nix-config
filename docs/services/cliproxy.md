# CLIProxyAPI on gizmo

CLIProxyAPI 在出口点 gizmo 上（为什么不在 tank：`docs/decisions.md#cliproxy-on-gizmo`），
模块 `system/modules/cliproxy`，主机配置 `hosts/gizmo/system.nix`。客户端用的模型表在
`lib/cliproxy-models.nix`。Rewind 插件另见 [Rewind](../rewind.md)。

## 两个入口 {#entrypoints}

两个入口用同一份调用密钥、模型和 OAuth 凭据，都只在 tailnet 内可达：

| 入口 | 地址 | 用途 |
| --- | --- | --- |
| HTTP | `http://gizmo.inner.imdomestic.com:8317/v1` | pi、OpenCode 和服务端客户端 |
| HTTPS | `https://gizmo.inner.imdomestic.com/v1` | fx 等要求非 loopback 地址必须用 TLS 的客户端 |

HTTP 不重定向到 HTTPS。HTTPS 的 nginx 只代理 `/v1/`，不转发 `/v0/management/` 等管理路径。
调用用 `cliproxy/api_key`，不是 `cliproxy/management_key`。

HTTPS 由 `hosts/gizmo/cliproxy-https.nix` 提供：

- 复用本机 nginx，在自己的 MagicDNS 地址监听 443；上游是 CLIProxy 的 Tailscale HTTP 地址。
  `my.tailscale.bindServices` 在启动前确认 DNS 答案属于本机 `tailscale0`，不退回 wildcard；
  443 只在 `tailscale0` 放行。
- 证书走原生 `security.acme` 的 Cloudflare DNS-01，复用 `ddns/cloudflare_token`（SOPS template
  提供 `CF_DNS_API_TOKEN`）。查询用 `1.1.1.1:53` 绕开 MagicDNS 的 SOA 限制
  （`docs/incidents.md#gaoji-acme-inner-soa`）。不加公网记录，但证书透明度日志会记下这个域名。
- nginx 等证书签发后、启动前验证证书链和域名；ACME 的临时自签证书不算上线
  （启动顺序的坑：`docs/incidents.md#cliproxy-https-dns01-ordering`）。
- 关闭请求和响应缓冲，读写超时一小时，支持 SSE 和 WebSocket；请求体上限沿用 50 MiB。

fx 的自定义 provider 用 `openai-chat-completions`，`base_url` 填 HTTPS 地址，Bearer 从
`CLIPROXY_API_KEY` 取：

```sh
export CLIPROXY_API_KEY="$(cat ~/.config/sops-nix/secrets/cliproxy/api_key)"
fx ask --no-save "只回复 OK"
```

检查：

```sh
just check-sops gizmo
ssh hank@gizmo 'systemctl status nginx acme-order-renew-gizmo.inner.imdomestic.com --no-pager'
ssh hank@gizmo 'systemctl list-timers acme-renew-gizmo.inner.imdomestic.com.timer --no-pager'
```

端到端检查要用正常的 TLS 校验，不能用 `curl -k` 或 ACME 单元成功代替：HTTP / HTTPS
`/v1/models`、无密钥被拒、管理路径 404、Chat / Responses 流式输出，以及 LAN / 公网地址上没有监听。
gizmo 的系统在 r6s 上构建；网络或防火墙改动先 `test` 激活。

## 模型目录 {#catalog}

`services.cliproxy.settings.models.catalog` 加载 `lib/cliproxy-catalog.nix` 生成的完整目录：
以 `router-for-me/models` 的固定提交为基线（URL 和 SHA-256 在这个文件里），在指定 provider
分组里按 ID 合并补充定义——已有 ID 的未覆盖字段保留，重复 ID 先删后写。仓库里不放原始 JSON，
目录里也没有任何密钥。用完整官方快照而不是软件包内嵌的表，是因为官方目录多出的型号会在内嵌表里丢掉。

自定义目录是**整体替换**，不是增量补丁；指定本地目录后 CLIProxy 也不再回退到官方 URL，
周期刷新只重读同一个文件。所以：

- 不能拿一个只含新增型号的 JSON 当完整目录。
- 升级 CLIProxy 软件包不会更新这份快照；升级快照时同时改 helper 的提交和 SHA-256，并检查其他
  provider 没丢。

### Codex GPT 6.2 {#codex-6-2}

`lib/codex-6.2.nix`：`gpt-6.2-sol`、`gpt-6.2-astra` 只合并进 codex-plus / pro / team 分组
（Free 账号的原生目录里没有这两个），不建指向旧型号的别名。

| 型号 | Codex 默认上下文 | 原生目录 max_context_window | 输出 |
| --- | --- | --- | --- |
| gpt-6.2-sol | 500000 | 872000 | 128000 |
| gpt-6.2-astra | 272000 | 872000 | 128000 |

公开 API 写的是 1.05M，但这里走 Codex 账号链路，客户端先用 Codex 自己的默认预算，不悄悄开
extended-context。原生目录里的 ultra（自动任务委派）不标成 max；Sol 原生目录有 audio，
但公开 API 只声明 text / image，客户端也只声明这两种。`bash scripts/check-pi-codex62.sh`
检查 Pi 的模型定义和完整目录的分组、上下文、输出、档位与价格。

### Hydrogen 的四个预设

`lib/antigravity-hydrogen.nix` 是服务端、Pi 和 Max 共用的型号数据：
`gemini-4-hydrogen-{low,medium,high,xhigh}` 是四个真实 Google ID，不用 `oauth-model-alias`
把它们映射到 XHigh；每个只声明与预设对应的 thinking level，不猜数字 budget
（依据和之前的误判：`docs/incidents.md#antigravity-hydrogen-effort`）。账号能不能用某个
预设仍由 Google 的账号目录决定。切换预设是 `/model` 选不同 ID，不是 `/effort`。

### 生效

只改文件不生效：gizmo 要部署系统来加载新目录，Pi 要激活 home，Max 要重载配置。
不需要重新编译 CLIProxy。上线后检查公开 `/v1/models` 里有新 ID，再对每个 ID 发一个短请求，
确认 `response.model` 是对应的原始 ID 而不是被路由到旧型号。
