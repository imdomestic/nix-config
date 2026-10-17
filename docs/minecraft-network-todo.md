# Minecraft 网络与 chorusd 待办

本文是 2026-10-17 一轮讨论定下的结论和待办。目前只到设计阶段，**下面没有一项已经开始做**。

相关文档和仓库：

- 旧服布局：`docs/encore-minecraft.md`
- chorus mod 的开发流程：`docs/chorus-development.md`
- chorusd 源码：私有仓库 `imdomestic/chorus-testbed`

## 结论速记

整个系统拆成两个互不依赖的部分：

| | chorusd | 运营网络 |
|---|---|---|
| 是什么 | 开源的通用 MC 开发测试工具：把任意 commit 的 mod 和任意版本的地图组合起来，拉起一台能进去玩的预览服 | 给玩家玩的服务器：大厅、生存、bingo |
| 主导 | linwhite | hank |
| 入口 | mc-router 这类纯透传：按主机名转发，不改协议内容 | Velocity 作唯一入口 |
| 编排 | 不用 Agones，靠租约、空闲计时，用服务器列表查询（SLP）判断状态 | Agones（Fleet、GSA、FleetAutoscaler） |
| 客户端 | 自己的 ruri-chorus（只有 macOS 版）；其他启动器用 mrpack | 玩家用任意启动器，不做定制启动器 |

两边不共用 Velocity、身份系统、集群和启动器。对 chorusd 来说，运营网络只是一个普通用户：用它给 bingo mod、大厅插件开预览服。

相关仓库：

| 仓库 | 作者 | 内容 |
|---|---|---|
| `imdomestic/chorus` | hank | 被测的 mod，MC 26.3，Fabric 和 NeoForge 两个版本 |
| `imdomestic/chorus-testbed`（私有） | linwhite | chorusd、hop-mod、部署脚本；接口约定写在 `docs/api.md` |
| `guh0613/ruri` → `imdomestic/ruri-chorus` | Genisys → linwhite | macOS 启动器，以及在它基础上做的 chorusd 前端分支 |
| `HCHogan/max` | hank | QQ bot，跑在 tank 上 |
| d2-map-dev | linwhite | 地图仓库，目前只在 linwhite 本机 |

## 现状（2026-10-17 核对）

- **现在没有面向玩家的服务器在跑。** 旧的 Velocity、bedrock-proxy、lobby、bingo、speedrun、GTL 全部被 `nixos/modules/chorus/legacy-minecraft.nix` 停用了。
- **k3s 只有一个 server，就是 encore。**
  - encore 是一台笔记本（见 `docs/encore-cooling.md`），网络走 WiFi `wlo1`。
  - 数据存储用默认的 SQLite，没开 `clusterInit`。
  - seraph 只是 agent。encore 一挂，集群就不会再调度任何东西。
- **encore 根分区 343G，已用 92%。** 占用大头是 `/home/linwhite` 153G、`/home/hank` 103G、`/nix/store` 45G。
- **chorusd 跑在 encore 上：**
  - 构建：systemd 单元 `chorus-build@`；
  - 房间：每个房间一个 StatefulSet 加一块 local-path PVC；
  - 入口：mc-router 加 `<room>.chorus.internal` 域名，只有 tailnet 内能连；
  - 归档：rsync 到 tank。
- **旧服数据都在 encore 本机，分散在几处：**
  - PostgreSQL 16：`minecraft`、`luckperms` 两个库；
  - MariaDB：`minecraft` 库，CMI 在用；
  - 代理的 LuckPerms：自己的 H2 文件；
  - SkinsRestorer：文件存储。

## 1. 先和 linwhite 对齐

- [ ] **现有 k3s 集群归谁。**
  - 建议交给运营网络。
  - chorusd 支持 Docker 后端之前，先留在这个集群里，占一个单独的命名空间。
  - 物理机就这几台，两边各起一套控制面，etcd 和高可用就得做两遍。
- [ ] **chorusd 所在命名空间默认拒绝网络访问。** 它的房间跑的是任意 mod，尤其不能碰运营侧的数据库。k3s 自带 NetworkPolicy 控制器，不用另装。
- [ ] **定 chorusd 的许可证，并改个名字，和 chorus mod 区分开。** ruri-chorus 继承了 ruri 的 GPL-3.0。
- [ ] **清理 encore 磁盘**：两个 home 目录各自清。

## 2. chorusd 开源化

这一节由 linwhite 主导，以下只是建议。

- [ ] **把运行后端抽象出来**：单机 Docker 优先，k8s 其次。大多数 mod 作者只有一台机器。
- [ ] **构建以"CI 把产物推进来"为主。**
  - 提供一个 GitHub Action：上传构建产物，并在 PR 评论里贴预览房间的地址。
  - 内置构建做成可选项，并放进容器里跑。构建任意仓库等于执行任意代码。
- [ ] **把写死的基础设施改成配置项：**
  - rsync 到 tank → 可配置的存储后端（本地目录或 S3）；
  - `chorus.internal` → 部署者自己的泛域名；
  - `users.toml` → GitHub OAuth 或 OIDC。
- [ ] **房间描述改用 mrpack。**
  - 用 Prism、HMCL 的人，下载 mrpack、复制服务器地址就能进。
  - 启动时加 `--quickPlayMultiplayer` 直接进房间；1.20 之前的版本用 `--server` 和 `--port`。
- [ ] **世界资产做成通用上传**，替换现在只给 d2map 用的发布命令。
- [ ] **不分发服务端 jar。** 运行时再下载，EULA 由部署者自己同意。
- [ ] 可选：每个 commit 自动开服跑一遍 gametest，和人工预览房间共用同一套组合逻辑。

以下保持不动：

- `docs/api.md` 的接口约定，ruri-chorus 依赖它；
- commit 图；
- 资产的 revision 机制，以及"地图用到的 namespace 必须在构建的 modIds 里"这条检查；
- 快照、种子、generation；
- 归档后的远端校验；
- SSE 事件流。

## 3. 运营网络：基础设施（nix-config）

- [ ] **encore 改接有线网**，没有网口就用 USB 网卡，并同步修改 `k3s-server.nix` 里的 `--flannel-iface`。etcd 成员跑在 WiFi 上，网络一抖就会重新选主。
- [ ] **k3s 从 SQLite 转成内嵌 etcd**：先备份，再设 `services.k3s.clusterInit = true`。
- [ ] **凑齐 3 个 etcd 投票成员。**
  - seraph 升为 server。
  - 第三个成员做成只跑 etcd 的见证节点：`--disable-apiserver --disable-controller-manager --disable-scheduler`。
  - 候选是 gizmo，它和 encore、seraph 在同一个 10.1.2.0/24 网段。但它是代理链的日本主出口，存储也不是 SSD，所以：
    - 先用 fio 测 fsync 延迟，确认内存够不够；
    - 再想清楚把集群和代理出口绑在同一台机器上值不值。
  - 不要用 tank 或 tokyo：跨公网延迟 98ms，etcd 会频繁重新选主。
- [ ] **入口用虚拟 IP**：kube-vip 或 MetalLB 的 L2 模式。tokyo 的转发改为指向这个 IP。
- [ ] **公网入口**：定域名；tokyo 转发 TCP 25565 和 UDP 19132（后者给 Geyser）。
- [ ] 装 Agones。
- [ ] 选 GitOps 工具：Flux 还是 Argo CD，还没定。
- [ ] **tank 上部署三样存储服务：**
  - 镜像仓库：`services.dockerRegistry`；
  - restic rest-server：`services.restic.server`；
  - Garage：`services.garage`，只存数据库备份。
- [ ] **CNPG 加 Barman Cloud Plugin，备份到 Garage。**
  - boto3 1.36 起会额外计算和校验 checksum，非 AWS 的 S3 会因此出错。在 `instanceSidecarConfiguration.env` 里设：
    - `AWS_REQUEST_CHECKSUM_CALCULATION=when_required`
    - `AWS_RESPONSE_CHECKSUM_VALIDATION=when_required`
  - S3 连不上时 WAL 会在本地堆积，要配告警。
- [ ] **迁移旧服数据：**
  - PostgreSQL 16 迁进 CNPG；
  - MariaDB 如果还要用，用 mariadb-operator 迁进来；
  - 代理的 LuckPerms 从 H2 合并进同一个数据库。
- [ ] Agones 的 Prometheus 指标接进现有监控。

## 4. 运营网络：游戏侧组件

### 身份

- [ ] **系统内部统一用一个玩家 ID。** 正版账号、外置登录账号、离线用户名，都只是绑定在这个 ID 上的登录凭据。
- [ ] **自建 Drasl。** nixpkgs 里已有 3.4.3 版本和 `services.drasl` 模块。
  - 没有正版的玩家通过 QQ bot 注册账号，同时绑定 QQ 号。HMCL、PCL 原生支持外置登录。
  - 部署位置还没定，前提是公网可达，启动器要能连上。
- [ ] **实测 Drasl 的 fallback。** 看能否让 Velocity 只认 Drasl 一家，就同时接受正版和 LittleSkin 账号。重点看 UUID 和重名怎么处理。
- [ ] **Velocity 多认证插件选型实测：**
  - MultiLogin：比较成熟，但不确定支不支持离线；
  - HyperZoneLogin：比较新，明确支持离线和外置混用。
- [ ] **真离线登录的兜底方案：**
  - 在 limbo 里 `/register`、`/login`；
  - 名字被正版或外置账号占用后，禁止再用离线登录；
  - 离线账号默认进最低权限组。
- [ ] 旧 LuckPerms 数据按新的 UUID 迁移。

### Velocity

- [ ] **路由插件**：只读监听 GameServer，注册和注销后端，按虚拟主机名路由。
- [ ] **玩家被房间踢出时，按 `getClientBrand()` 分流：**
  - Fabric 和原版客户端送回大厅；
  - Forge、NeoForge 客户端直接断开，并给出提示。
- [ ] **放宽聊天签名检查**，照顾装了 No Chat Reports 的客户端：
  - Velocity 设 `force-key-authentication = false`；
  - 后端设 `enforce-secure-profile=false`。
- [ ] Geyser + Floodgate，给基岩版用。
- [ ] **定 GameServer 的标签约定**，至少包括：
  - 路由用的主机名；
  - 接受哪类客户端（`vanilla`、`fabric-pack`、`forge-pack`）；
  - 服务器类型。

  这只是运营网络内部的约定，不对外。

### Agones 集成（Java）

- [ ] **结构**：core（Agones REST 客户端、空闲计时、玩家列表）加 paper、fabric 两个适配层。
- [ ] **健康检查**：
  - `Health()` 在 tick 里调用；
  - 服务器还没开始 tick 的启动阶段，先用后台线程 ping；
  - `failureThreshold` 调到总共约 60 秒，扛得住 GC 和存盘造成的卡顿。
- [ ] 玩家进出时增删 `players` 列表。这用的是 Agones 的 Lists 功能，目前还是 beta。
- [ ] **空闲回收**：空闲 N 分钟后调 `Shutdown()`，N 从 GameServer 注解读取。存盘和归档必须在 `Shutdown()` 之前做完。
- [ ] **大厅的状态切换**：第一个人进来时调 `Allocate()`，人走光后调 `Ready()`。
- [ ] **端口设置**：`protocol: TCP`（默认是 UDP），`portPolicy: None`。

### 大厅

- [ ] **Paper 最新版，加 ViaVersion、ViaBackwards、ViaRewind。** 这三个插件装在大厅上，不装在 Velocity 上。
- [ ] **只用所有版本的原版客户端都认得的东西**：箱子菜单、告示牌、命令。资源包设为可选。
- [ ] **Fleet + FleetAutoscaler**，用 List 策略按剩余空位扩缩。

### bingo 与匹配

- [ ] **确认 bingo 的 mod 只需要装在服务端**，否则原版和基岩版客户端进不去。
- [ ] Fleet + FleetAutoscaler 的 Buffer 策略，保持几台热备。
- [ ] **匹配服务：**
  - 队列和组队信息先放内存；
  - 凑够人就发起 GSA 分配，分组信息写进 metadata；
  - 通过事件流通知 Velocity 把玩家送过去；
  - RBAC 只允许它写自己的命名空间；
  - 不用 Open Match。
- [ ] 对局结束后，由 mod 调 `Shutdown()`。

### 生存服

- [ ] **用 StatefulSet + PVC 部署，不用 Agones。** 加一个 itzg/mc-backup sidecar，备份到 restic。Agones 的思路是"挂了就删、换一台新的"，不适合长期保存的世界。
- [ ] **GTL（Forge 1.20.1）客户端只能经专用主机名直接进服。** 后端需要装 proxy-compatible-forge。旧代理上的 Ambassador 1.4.5 可以沿用。

### 聊天

- [ ] **MC 聊天和 QQ 群互通。** 给 max 写一个 MC 平台适配器，由 Velocity 插件把聊天流接出来。

## 5. 运营网络：构建与发布

- [ ] **每个 commit 由 GitHub Actions 构建。**
  - 含 Mojang 服务端 jar 的基础镜像只推到 tank 的私有仓库，由 tank 上的自托管 runner 构建。
  - **自托管 runner 只给私有仓库用。** 公开仓库的 `pull_request` 绝不能触发它。
- [ ] **要公开给开发者的东西：**
  - 镜像发到 ghcr；
  - jar 发到 R2 上的静态 Maven 仓库。不用 GitHub Packages，因为它的 Maven 仓库即使公开，拉取也要 token；
  - 版本号：每个 commit 发 `x.y.z-g<sha12>`，每个分支维护一个 `<branch>-SNAPSHOT`。
- [ ] **上线方式**：通过 GitOps 提 PR，修改 Fleet 的镜像 tag。滚动更新只替换处于 Ready 状态的服，正在进行的对局会打完再结束。
- [ ] 上线前先用 chorusd 开预览服测一遍。

## 不做的事

- **Shulker**：只支持 Paper、Folia、Minestom，自带的匹配功能还是 alpha。
- **Open Match**：对我们这个规模来说太重。
- **MinIO**：上游已经归档，S3 改用 Garage。
- **zot**：nixpkgs 里没有，镜像仓库改用 Distribution。
- **给玩家做定制启动器**：玩家用任意启动器就行。
- **游戏内下载 mod（比如 AutoModpack）**：mod 只在游戏启动时加载，每切一次房间就得重启游戏。改为由启动器在进游戏前同步。
- **世界做高可用**：同一个世界同一时间只能有一个进程写入。可用性靠 restic 快速恢复。
