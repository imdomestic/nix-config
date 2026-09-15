# Max SSH 运维接入

Max 的 `services.max.operations` 模块提供专用 tailscaled、`maxops` netns 和
群聊 sandbox 的网络选择。基础实现与迁移脚本在 Max 仓库，fleet 配置在本仓库。

## 本仓库的配置

- `nixos/modules/max-operator.nix`：NixOS / nix-darwin 的 `max` 运维账户，完整免密 sudo。
  macOS 使用 UID 550；首次激活前核对本机该 UID 未被其他账户占用。
- `nixos/hosts/h610/max.nix`：开启 QQ 群 611798505、650536599 的 SSH 运维网络；
  Max 进程及渲染配置的所有者是 `max-service`。
- `nixos/hosts/h610/system.nix`：`max@imdomestic.com` 加入 `group:imdomestic`，
  专用 veth `max-ops-host` 加入 DAE 的转发入口，沿用现有内网直连与外网代理规则。
- `secrets/hosts/h610-ops.yaml`：sops-nix 管理的独立 preauthkey；由 systemd
  `LoadCredential` 交付给专用客户端。节点状态保存在 `/var/lib/max/tailscale`。

群内成员均可发起运维。模型加载 `operations` skill 后使用普通 `ssh hostname`，
默认登录 `max`。Tailscale SSH 目标必须已在自己的客户端上开启 SSH；这里不替换
macOS 的现有 VPN 客户端或更改它的服务管理方式。

## 版本与验证

`flake.lock` 将 Max 固定到已发布的 SSH 运维实现。正常求值无需本地覆盖：

```sh
nix eval --raw .#nixosConfigurations.h610.config.system.build.toplevel.drvPath
```

所有 NixOS 与 nix-darwin 系统分别求值。Max 仓库提供真实 Headscale/Tailscale
的 `operations` VM 检查，以及 `sandbox-network`、`state-migration` 和
`nixos-reload` 回归检查。

## 旧运维服务移除

旧 Hub、Agent、Executor、API 凭据、Alertmanager 的 Hub 转发出口和专用检查
脚本已移除，flake 也不再依赖旧 maxops 仓库。Prometheus 和 Alertmanager 保留；
告警默认仍可在 Alertmanager 查看，独立 webhook 配置继续有效。

Gaoji 的控制服务、计算 worker、认证凭据和主机清单保留，主机元数据改用
`clusterControl`。旧 Hub 支持的 Gaoji ops／部署入口已移除。Gaoji 控制和
h610 worker 的密钥分别迁到 `secrets/gaoji/control.yaml`、`worker-h610.yaml`。
历史决策与故障记录保留，用于解释已经部署过的版本。

## 首次切换顺序

1. 构建新的 h610 系统，记录新 store path 和原 generation。
2. 停止 `max-stack.target`，运行新系统的 `max-migrate-service-account --check`
   和 `--migrate`。脚本保留旧服务 UID/GID，将名称改为 `max-service`；数据库/角色
   继续叫 `max`，通过 PostgreSQL peer map 登录。
3. 激活 h610 新系统；新 `max` 登录账户与旧服务 UID 分离。未先迁移时 pre-switch
   检查会阻止激活。
4. 按 fleet 的 builder 约定构建并激活其他目标。此账户变更属于系统闭包，
   不需要 Home Manager activation。
5. 检查 Max/数据库/broker 与业务功能，再从已开启的群执行 `ssh hostname`
   和 `sudo -n id -u`，验证 MagicDNS、子网路由、重启后节点身份及工作区保留。

完整生命周期和故障恢复见 Max 仓库 `docs/runbooks/ssh-operations.md`。
构建和 VM 测试不等同于线上切换或真实群聊验收。
