# Max SSH 运维接入

Max（maxx，跑在 tank 上）让指定群聊的 VM 用普通 `ssh <host>` 以 `max` 身份运维整个车队。

## 本仓库的配置

- `system/modules/max-operator.nix`（经 `system/modules/users.nix` 导入，所有 NixOS /
  nix-darwin 主机都有）：`max` 账户，完整免密 sudo，没有密码。macOS 上 UID 550，
  首次激活前核对该 UID 没被占用。
- `hosts/tank/maxx.nix` 的 `services.maxx.vm.operations`：哪些会话（按 maxx 的会话 ID）
  的 VM 走运维网络；VM 经 `maxops` 节点上 tailnet，节点状态在 `/var/lib/maxx-ops-tailscale`
  （2026-11-05 从旧 Haskell Max 复制过来）。`hostAddress` 是 tank 自己的 tailnet 地址，
  让这些 VM 也能经 Tailscale SSH 进 tank。运维子网的 ip rule 必须写在 `br-lan` 的
  networkd 文件里，否则 networkd 会把它删掉（文件里的注释有原委）。
- `hosts/h610/system.nix`：Headscale 策略里 `max@imdomestic.com` 属于 `group:imdomestic`。

Tailscale SSH 的目标机必须在自己的客户端上开启 SSH；在 tailnet 地址上 22 端口是
Tailscale SSH，不到 sshd。Max 自己的运维流程在 Max 仓库的 `docs/runbooks/ssh-operations.md`。

旧 maxops（Hub、Agent、Executor）已移除；Gaoji 的控制服务和 worker 保留，主机元数据用
`clusterControl`。

## 2026-09-15 fleet rollout {#2026-09-15-fleet-rollout}

`max` 账户第一次铺到全车队。当时 Max 还在 h610，下表是用户当次指定的构建分工，
不是以后的默认做法（默认见 AGENTS.md「小内存机器不在自己身上编译」）：

| 目标 | 构建位置 | 结果 |
| --- | --- | --- |
| h610 | h610；tank 复核相同闭包 | 激活，验收通过 |
| tank、shanghai | tank | 激活，验收通过 |
| r2s、r5s、gizmo、r6s | r6s | 激活，验收通过 |
| b650（现 taipan） | 本机 | 激活，验收通过 |
| rpi4 | 本机，单任务、2 核、2 GiB 构建上限 | 激活，验收通过 |
| h310 | 本机，单任务、2 核、4 GiB 构建上限 | 系统生效，验收通过；switch 返回 4 |

h310 本机构建是因为 tank 到 h310 的闭包传输不稳定，直接 fetch 加构建约 1 分 39 秒。
它的 switch 返回 4 是旧 Gaoji 安装 oneshot 下载 whisper.cpp 超时，与这次改动无关；
不要为了零退出码盲目重跑 switch。

验收是从 Max 沙箱对 10 台主机 `ssh` 登录 `max`、`sudo -n id -u` 为 0、运行闭包与目标一致、
Tailscale 节点身份不变。Darwin / WSL 配置只求值过，不代表已经远程部署。
