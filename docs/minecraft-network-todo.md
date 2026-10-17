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

运营网络各部分的管理方式：

| 内容 | 怎么管 |
|---|---|
| 节点：k3s 本身、etcd、网卡、镜像源 | NixOS |
| 集群里装的东西：Agones、CNPG、Velocity、各个 Fleet 等 | 用 nixidy 写，渲染成 YAML，由 Argo CD 应用 |
| 运行时对象：分配出来的服、Pod | 不写进配置，由控制器创建 |
| mod、插件、匹配服务的源码 | 放在 nix-config 顶层的 `minecraft/`，由 GitHub Actions 构建；Nix 不构建任何 mod 或镜像 |

相关仓库：

| 仓库 | 作者 | 内容 |
|---|---|---|
| `imdomestic/chorus` | hank | 被测的 mod，MC 26.3，Fabric 和 NeoForge 两个版本 |
| `imdomestic/chorus-testbed`（私有） | linwhite | chorusd、hop-mod、部署脚本；接口约定写在 `docs/api.md` |
| `guh0613/ruri` → `imdomestic/ruri-chorus` | Genisys → linwhite | macOS 启动器，以及在它基础上做的 chorusd 前端分支 |
| `HCHogan/max` | hank | QQ bot，跑在 tank 上 |
| d2-map-dev | linwhite | 地图仓库，目前只在 linwhite 本机 |

## 现状（2026-10-17 核对）

- **encore 上的旧服全部停用了。** 旧的 Velocity、bedrock-proxy、lobby、bingo、speedrun、GTL 都被 `nixos/modules/chorus/legacy-minecraft.nix` 停用。
- **运营集群（2026-10-17 起）是 tank 上的单节点 k3s。**
  - 节点配置在 `nixos/hosts/tank/k3s.nix`，集群内容在 `k8s/`，由 Argo CD 从 `k8s-rendered` 分支同步。
  - 目前跑着一套用旧存档搭的测试网络：Velocity + 大厅（Paper 1.21.1）+ bingo（Fabric 1.21.11）。
  - 大厅已经是 Agones Fleet：`minecraft/agones-paper` 上报状态，Velocity 上的 `minecraft/velocity-router` 动态注册后端。bingo 还是 StatefulSet。
  - 测试网络是离线模式，在 tailnet 内连 `tank.inner.imdomestic.com:25565`。tank 的防火墙是关着的，局域网 192.168.20.0/24 也能连。
  - kubectl 和 k9s 用 `tank` 这个 context，见 `home/modules/kube`。
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

- [x] **集群归属（2026-10-17 定）**：运营网络在 tank 上单独起一个单节点 k3s，encore 上的 k3s 继续归 chorusd，两边互不影响。
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

运营集群目前是 tank 上的单节点 k3s。下面关于 encore 有线网、etcd 三个成员和虚拟 IP 的几项，原本是针对 encore 上的集群写的；等运营集群需要高可用时，再按届时的机器重新规划。

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
- [x] **集群里装的东西用 nixidy + Argo CD 管理。**
  - nixidy 作为 flake 输入，集群配置写在顶层的 `k8s/` 目录。
  - Agones、CNPG 的 CRD 生成带类型的选项；它们的 Helm chart 由 Nix 按 hash 固定版本，再渲染成普通 YAML。
  - CI 在 main 上渲染，推到一个专门的分支，比如 `k8s-rendered`。Argo CD 跟踪这个分支，配置里删掉的资源也由它清理。
  - 本地加一个 `just k8s-diff`：渲染后跑 `kubectl diff`。
  - NixOS 只负责引导：用 `services.k3s.autoDeployCharts` 装上 Argo CD 和根 Application。其他集群内容不写进 `services.k3s.manifests`，因为删掉 manifest 文件不会删掉对应的资源。
  - Fleet 的配置里不写 `replicas`，或者在 Argo CD 里对 `/spec/replicas` 设 `ignoreDifferences`。否则 FleetAutoscaler 和 Argo CD 会来回改这个字段。
- [x] **密钥走 sops-nix。**
  - 由 server 主机把 Secret manifest 写进 k3s 的 manifests 目录，复用现有的 sops 流程和 `just check-sops`。
  - 渲染出来的 YAML 里不能有任何密钥：仓库和渲染分支都是公开的。
- [x] 用 nixidy 装 Agones（Helm chart）。证书的处理见 `k8s/apps/agones`。
- [ ] **临时操作可以直接用 kubectl**（查看、drain、紧急扩缩），但事后要把改动写回配置。Argo CD 的自动修复会把手动改动改回去，紧急情况下先暂停自动同步。
- [ ] **tank 上部署三样存储服务：**
  - 镜像仓库：`services.dockerRegistry`。只在需要私有镜像时才用得上，见第 5 节；
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

- [x] **路由插件**（`minecraft/velocity-router`）：只读监听 GameServer，按 Pod IP 注册和注销后端，进服和被踢时选大厅，提供 `/lobby`。按虚拟主机名路由还没做。
- [ ] **玩家被房间踢出时，按 `getClientBrand()` 分流：**
  - Fabric 和原版客户端送回大厅；
  - Forge、NeoForge 客户端直接断开，并给出提示。
- [ ] **放宽聊天签名检查**，照顾装了 No Chat Reports 的客户端：
  - Velocity 设 `force-key-authentication = false`；
  - 后端设 `enforce-secure-profile=false`。
- [ ] Geyser + Floodgate，给基岩版用。
- [x] **ViaVersion、ViaBackwards、ViaRewind 装在 Velocity 上**，大厅、bingo 等所有原版兼容的后端都能覆盖到。
  - 路由插件注册后端时，调用 `ProtocolDetectorService.setProtocolVersion` 告诉 Via 这个后端的版本；注销时调用 `uncacheProtocolVersion`。
  - 不这么做的话，新房间在 Via 第一次探测到它的版本之前，会被当成 Velocity 支持的最低版本。
- [ ] **带 mod 的房间（`fabric-pack`、`forge-pack`）要求客户端版本完全一致。** 版本不符时由路由插件直接拒绝并给出提示，不让 Via 去翻译。
- [ ] **定 GameServer 的标签约定**（`mc.imdomestic.com/kind` 和 `mc.imdomestic.com/protocol` 已经在用），至少包括：
  - 路由用的主机名；
  - 后端的协议版本号；
  - 接受哪类客户端（`vanilla`、`fabric-pack`、`forge-pack`）；
  - 服务器类型。

  这只是运营网络内部的约定，不对外。

### Agones 集成（Java）

- [ ] **结构**：core（Agones REST 客户端、空闲计时、玩家列表）加 paper、fabric 两个适配层。core 和 paper 已完成（`minecraft/agones-core`、`minecraft/agones-paper`），fabric 还没做。
- [x] **健康检查**：
  - `Health()` 在 tick 里调用；
  - 服务器还没开始 tick 的启动阶段，先用后台线程 ping；
  - `failureThreshold` 调到总共约 60 秒，扛得住 GC 和存盘造成的卡顿。
- [x] 玩家进出时增删 `players` 列表。这用的是 Agones 的 Lists 功能，目前还是 beta。
- [ ] **空闲回收**：空闲 N 分钟后调 `Shutdown()`，N 从 GameServer 注解读取。存盘和归档必须在 `Shutdown()` 之前做完。
  - 已实现 ROOM 模式（存盘后 Shutdown），空闲时长目前读环境变量 `MC_AGONES_IDLE_SECONDS`，还没改成读注解，也还没实测。
- [x] **大厅的状态切换**：第一个人进来时调 `Allocate()`，人走光后调 `Ready()`。
- [x] **端口设置**：`protocol: TCP`（默认是 UDP），`portPolicy: None`。

### 大厅

- [ ] **Paper 最新版。** 跨版本兼容由 Velocity 上的 Via 负责。如果以后想认真照顾 1.8 客户端的体验，再看 Paper 端还需要补哪些修正，有一部分修正只能装在后端。
- [ ] **只用所有版本的原版客户端都认得的东西**：箱子菜单、告示牌、命令。资源包设为可选。
- [ ] **Fleet + FleetAutoscaler**，用 List 策略按剩余空位扩缩。Fleet 已经上线，目前用的是 Buffer 策略：始终留一台空大厅待命。

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

- [x] **源码放在 nix-config 顶层的 `minecraft/` 目录，不放 `pkgs/`。** `pkgs/` 里的东西会进入 flake 的 `packages` 输出，被 CI 构建后推到公开的 cachix。
- [x] **构建全部交给 GitHub Actions，Nix 不构建任何 mod 或镜像。**
  - Nix 只提供开发环境：`nix develop` 里的 JDK 和 Gradle。
  - 工作流按路径过滤：`minecraft/**` 的改动不触发主机的 dry-build 矩阵，主机配置的改动也不触发 mod 构建。
- [x] **镜像里不打包 Mojang 的服务端 jar。**
  - 原因：nix-config 是公开仓库，不能挂自托管 runner。fork 提交的 PR 会用 PR 里改过的工作流文件来运行，可以直接指定这个 runner。
  - 我们自己的镜像只包含自己的 jar，在 GitHub 托管的 runner 上构建，公开推到 ghcr。
  - 服务端 jar 由 itzg 镜像在启动时按固定版本下载。
  - 如果启动时下载拖慢了扩容，再把服务端 jar 单独做成按 MC 版本区分的私有镜像（很少变，放在 tank 上），通过 image volume 挂进容器。
- [x] **镜像 tag 用源码的内容哈希**：目前按整个 `minecraft/` 目录算（`minecraft/image-tag.nix`），没有按组件拆。
- [x] **ghcr 上新建的包默认是私有的**，集群匿名拉取会 401。`mc-lobby`、`mc-proxy` 已手动改成公开，以后新增的镜像也要在 GitHub 上改一次。
  - CI 构建镜像时和 nixidy 渲染时，用同一个 `nix eval` 表达式算出同一个值，不需要机器人提交来改 tag。
  - 同一个工作流里先推镜像，再推渲染分支，避免 Argo CD 去拉一个还不存在的镜像。
- [ ] **测试和上线：**
  - PR 的构建产物上传到 chorusd，开预览服测试。只有仓库内分支的 PR 能这么做，fork 的 PR 拿不到密钥。
  - 合并到 main 后自动上线。Fleet 滚动更新只替换 Ready 状态的服，正在进行的对局会打完再结束。
- [ ] **要公开给开发者的东西：**
  - 镜像发到 ghcr；
  - jar 发到 R2 上的静态 Maven 仓库。不用 GitHub Packages，因为它的 Maven 仓库即使公开，拉取也要 token；
  - 版本号：每个 commit 发 `x.y.z-g<sha12>`，每个分支维护一个 `<branch>-SNAPSHOT`。

## 不做的事

- **Shulker**：只支持 Paper、Folia、Minestom，自带的匹配功能还是 alpha。
- **Open Match**：对我们这个规模来说太重。
- **MinIO**：上游已经归档，S3 改用 Garage。
- **zot**：nixpkgs 里没有，镜像仓库改用 Distribution。
- **给玩家做定制启动器**：玩家用任意启动器就行。
- **游戏内下载 mod（比如 AutoModpack）**：mod 只在游戏启动时加载，每切一次房间就得重启游戏。改为由启动器在进游戏前同步。
- **世界做高可用**：同一个世界同一时间只能有一个进程写入。可用性靠 restic 快速恢复。
- **用 Nix 构建 mod 和镜像**：这些产物是给集群用的，不是给 NixOS 主机用的。用 Nix 构建还得另外锁一份 Gradle 依赖，而 Fabric 的 Loom 会自己下载 MC 本体，在 Nix 沙箱里很难构建。
- **把集群内容写进 `services.k3s.manifests`**：删掉 manifest 文件不会删掉资源，而且每次发布都要对主机做一次 switch。
- **在 nix-config 上挂自托管 runner**：仓库是公开的，fork 的 PR 能指定这个 runner。
- **命令式管理集群**：改动无从追溯，控制面重建时也没法恢复。
