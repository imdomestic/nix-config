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

下面仅用于尚未迁移的安装。已经运行 `max-service` 的 h610 不要重复账号迁移。

1. 构建新的 h610 系统，记录新 store path 和原 generation。
2. 显式停止并等待 `max-stack.target`、`max.service`、`max-runtime.service` 和
   `max-runtime.socket`，确认旧服务 UID 没有残留进程，再运行新系统的 `max-migrate-service-account --check`
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

## 运行时约定

- `maxops` 是共享 netns 和客户端节点名，入站 SSH 关闭；连接目标填实际 fleet 主机，
  例如 `ssh h610`。模型无需使用专门的 SSH 子命令或寻找 Hub API。
- `operations` 技能加载 sandbox 工具；网络由 broker 按群配置选择，加载技能和
  选择后台 task profile 都不会改变网络权限。已开启群的 shell 可完整运维。
- 专用客户端与网络属于 `max-stack.target`，资源放在 `max.slice`；普通重启
  `max.service` 不重启客户端。节点状态、preauthkey 和控制 socket 不交给 sandbox。
- 同一 sandbox 的独立命令可并发，不再由单个后台任务独占；每条命令保留独立的
  systemd 执行单元、超时和输出。删除及策略重建等待活动命令结束，同路径写入和
  同一主机部署由调用者协调。这项行为随新的 Max 版本激活生效。
- 共享 netns 包括 localhost 和端口空间，临时服务使用动态端口。各 sandbox 的
  `/work` 仍分别保留；升级不会更新其中的 Git clone，也不会改写旧 monitor/task 目标。
- Max 当前实现以 `self-knowledge` / `inspect_source` 的 build revision 为准；修改
  仓库前核对远端、HEAD 和未提交改动，用独立 worktree。旧任务引用的 MaxOps API
  是历史信息；检查原目标与远端状态后使用当前 SSH 流程，不能重放旧 job。
- 内嵌技能和提示词需要新的 Max 构建及激活才生效。DB-global/群技能可以覆盖 builtin，
  已加载技能在当前执行内固定；文档提交不会替换已有任务的加载记录。

## 2026-09-15 fleet rollout

发布基线：Max `cfcbba9b0a8b07159c396967ce24fafe2e598216`，
nix-config `3071dc2e5df69686ad1f5f195606060b9f8df7b2`。
下表记录当次用户指定的构建分工，不覆盖以后任务的新指令。

| 目标 | 构建位置 | 本次结果 |
| --- | --- | --- |
| h610 | h610（先行部署）；tank 复核相同目标闭包 | 已激活，Max/broker/数据库及 SSH 验收通过 |
| tank、shanghai | tank | 构建、激活、SSH 验收通过 |
| r2s、r5s、r5sjp、r6s | r6s | 构建、激活、SSH 验收通过 |
| b650 | b650 | 本机构建、激活、SSH 验收通过 |
| rpi4 | rpi4，单任务、2 核、2 GiB 构建上限 | 本机构建、激活、SSH 验收通过 |
| h310 | h310，单任务、2 核、4 GiB 构建上限 | 目标系统已生效，SSH 验收通过；switch 返回 4，见下 |

tank 到 h310 的闭包传输不稳定，按用户指令改为 h310 直接 fetch、下载并构建，
约 1 分 39 秒完成；构建产物未经过操作者的跨境工作站中转。所有远端使用干净的
`/home/hank/max-fleet-deploy-20260915` worktree，保留原 checkout 的独立改动。

从 h610 的 Max 沙箱，以 `max-service` 调用真实 broker，对以上 **10/10** 主机
执行普通 SSH，确认登录 `max`、`sudo -n id -u` 为 0、运行闭包与目标一致、原
Tailscale 节点身份未变。另核对系统 profile 相同，旧 `maxops*` unit 文件均消失。
验收沙箱及卷已删除。Darwin/WSL 配置求值不代表这些机器已经远程部署或通过 SSH。

h310 的旧 Gaoji 安装 oneshot 在激活 target 时被重试，下载 whisper.cpp 达到
180 秒超时，再次失败；因此 switch 返回 4，部署 unit 保留失败证据。新系统及
profile 均已切换，运维验收通过。这不是严格系统健康通过，不能为得到零退出码
盲目重跑 switch。r2s 的 `network-rps` 已恢复；另有短 SSH 进程提前退出造成的
`session-c10.scope` 失败。Max 原有投递债务也未被清除或重放。

证据保存在 h610 的 `/var/lib/max/backups/ssh-operations-20260915/`：
`fleet-acceptance.json` 是逐机验收，`fleet-deployment-result.json` 记录版本、闭包、
构建分工与异常。其他目标在 `/var/lib/max-fleet-deploy/20260915/` 保留原系统、
Tailscale 状态、切换前失败单元与激活脚本。备份含私有状态，不应作为聊天附件发布。
