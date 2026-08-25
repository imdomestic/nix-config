# QQ Bot PostgreSQL 高可用与容量设计

## 目标

机器人使用一套独立的 PostgreSQL 17 集群，不再依赖 Tank 上同时承载
Matrix、Minecraft 的 5432 集群。

- h610 是首选主数据节点，Tailscale 地址 `100.64.0.3:55432`，优先级 100。
- Tank 是热备数据节点，Tailscale 地址 `100.64.0.4:55432`，优先级 50。
- h610 同时运行 `pg_auto_failover` monitor，端口为 `55431`。
- 两个数据节点都在线时使用同步流复制。
- Tank 离线时 h610 继续提供写入；连接串会自动选择当前可写节点。
- Tank 恢复后只作为副本追平，不自动提升为主库。

应用连接串同时列出两个节点，并带有
`target_session_attrs=read-write`。机器人不会把只读副本误认为主库。

## 访问安全

- monitor、复制和 `pg_rewind` 使用独立的 64 位十六进制 HA 口令，保存在 SOPS 中，
  不与机器人应用账号共用。
- monitor 与两个数据节点都只监听各自的 Tailscale 地址，跨机器连接同时要求 TLS
  和 SCRAM-SHA-256。
- `postgres` 超级用户只允许通过本机 Unix socket 的 peer 认证登录，所有网络登录
  会在 HBA 第一层被拒绝，即使上游工具以后又追加了宽松规则也不会绕过。
- `qq_bot` 是无建库、无建角色、无复制权限的应用账号，只允许从 h610 的精确
  Tailscale 地址访问 `qq_bot` 数据库。

自签名证书在当前 Tailscale 私网中负责链路加密；节点身份还依赖 Tailscale。
未来把 monitor 迁往第三台主机时，建议同时换成私有 CA 签发的证书和
`sslmode=verify-full`，进一步验证 PostgreSQL 服务端身份。

## 防止双主

不能用“先连 Tank，失败就直接写 h610”这种普通重试实现高可用。网络分区时，
两台机器可能都认为对方已死，最后产生两份无法自动合并的数据。

本方案由 monitor 保存唯一的节点状态机。副本只有收到明确的提升状态后才开放
写入；旧主重新上线时会先被降级，再通过 `pg_rewind` 或全量基础备份追上新主。

正式生产形态应把 monitor 放到第三台独立、常在线的小主机或 VPS。它只保存集群
状态，几乎不消耗磁盘；14T 与 1T 的容量差异不会影响它。当前先把 monitor 放在
h610 上。这个形态能防止双主，但不是完整三节点 HA：
若 h610 整机离线，Tank 会同时失去 monitor 和副本，并为避免双主而自我停写。

等第三台仲裁机确定后，需要先迁移 monitor 状态，再把两个 keeper 的 monitor URI
一起切换过去；不能直接在新地址创建一个空 monitor。数据库仍只放在 Tank 与 h610，
第三台机器不保存业务数据。

## 容量边界

2026-08-11 实测：h610 物理盘只有 `476.9G`，并非完整可用的 1T；根分区剩余约
`137G`。机器人现有状态总量约 `71M`。因此 h610 足以保存机器人专用数据库的
完整热备，但不能镜像 Tank 的 14T 文件空间。

PostgreSQL 只保存：

- 消息、会话上下文和用户资料
- 模型偏好、提醒、任务与投递状态
- 工具调用日志和用量记录
- embedding 向量及其文本元数据

PostgreSQL 不保存：

- QQ 图片、语音、视频和群文件二进制
- 沙盒镜像、构建缓存和大体积产物
- 长期文件归档

这些大对象放在 Tank 的文件/对象存储层，数据库只保存标识、路径、哈希、大小和
生命周期。Tank 离线时，机器人核心聊天和记忆仍可用；仅依赖旧大文件的功能会
暂时不可用。若要求 Tank 离线时历史大文件也全部可用，必须增加第三份对象存储，
不能用 h610 的小盘凭空替代 14T。

## 小盘保护

h610 的保护参数：

- 复制槽最多保留约 `16GB` WAL
- 常驻 WAL 约 `1GB`，`max_wal_size` 为 `4GB`
- 本地只保留最新 1 份已验证逻辑备份，且最长保留 3 天
- 做备份后必须仍能预留至少 `30GB` 空间
- PostgreSQL collector 日志保留 7 天
- 每周把最新逻辑备份恢复到一次性 PostgreSQL 实例并检查 Schema

Tank 的保护参数：

- 复制槽最多保留约 `32GB` WAL
- 逻辑备份最多保留 30 份、30 天
- 做备份后必须仍能预留至少 `200GB` 空间
- 主库和副本都各自在本机执行 `pg_dump`，避免备份只存在 h610
- 每周独立执行一次恢复验证

当一台副本离线过久、所需 WAL 已超过上限时，它恢复后需要重新做基础备份。这比
让当前主库磁盘被无限 WAL 填满更安全。

物理复制要求两台节点拥有同样完整的 PostgreSQL 数据，因此热数据库的长期容量
上限必须按 h610 的小盘计算，而不是按 Tank 的 14T 计算。达到容量预警线前，应把
旧原始消息、工具日志和媒体索引归档为 Tank 上的压缩冷数据，只在热库保留近期
原文、摘要、固定记忆和仍会检索的向量。Tank 离线时旧归档暂不可读，但聊天、近期
上下文和核心记忆不受影响。

## 日常命令

查看节点状态：

```bash
sudo qq-bot-postgres-status
sudo qq-bot-postgres-health
```

查看服务日志：

```bash
systemctl status qq-bot-postgres-monitor
systemctl status qq-bot-postgres-node
journalctl -u qq-bot-postgres-node -n 100 --no-pager
journalctl -u qq-bot-postgres-health -n 100 --no-pager
```

`qq-bot-postgres-health` 不只看 systemd 进程，还会同时核对本机 PostgreSQL、
monitor 注册、节点角色和最近上报时间。keeper 活着但数据库已停止时，该命令会失败，
并把结果写到 `/run/qq-bot-postgres-health/health.json`。定时器每 30 秒检查一次。

日常 `nixos-rebuild` 不会创建、删除或重建节点身份。节点配置或 PGDATA 缺失时，
服务会快速失败并要求管理员运行显式注册命令：

```bash
sudo qq-bot-postgres-enroll-local --confirm-enroll
```

该命令仅用于全新、没有旧身份和 PGDATA 的节点。已有数据节点必须使用下面的受控
重建流程，不能用 enroll 覆盖。

数据节点的 unit 或软件包变化也不会在 rebuild 时自动重启 PostgreSQL。需要升级
keeper 或应用新 PostgreSQL 配置时，必须先确认另一个节点健康，再逐台显式重启，
避免一次系统切换同时扰动主库和副本。

## 故障恢复闭环

强制移除节点前必须先在故障节点执行持久化隔离：

```bash
sudo qq-bot-postgres-fence-local --confirm-fence
```

该命令先写入节点状态目录中的 `FENCED`，再停止 keeper，并确认 PostgreSQL 端口
关闭。`FENCED` 会让后续 rebuild 和重启继续保持隔离，避免旧节点带着过期身份复活。

确认剩余主库健康并完成必要的 monitor 操作后，在被移除的节点执行：

```bash
sudo qq-bot-postgres-rejoin-local --confirm-rebuild-from-primary
```

rejoin 会拒绝以下危险情况：monitor 仍注册着同名节点、没有新鲜可写主库、或者磁盘
不足以同时保留旧数据和接收新副本。检查通过后，它会：

1. 再次隔离本机并确认端口关闭。
2. 将旧 PGDATA、pg_autoctl 配置和运行状态改名为带时间戳的 `pre-rejoin` 目录，
   不直接删除。
3. 从 monitor 当前认可的主库执行基础同步并注册新节点身份。
4. 启动 keeper，最多等待一小时，直到本机与 monitor 一致且成为健康副本。
5. 输出旧 PGDATA 的保留路径，供人工确认稳定后再择期清理。

恢复只有在 `sudo qq-bot-postgres-health` 成功、monitor 同时显示 h610 为可写主库且
Tank 为 `secondary` 后才算完成。不能把单节点 `single` 状态当作长期恢复成功。

手动验证逻辑备份：

```bash
sudo systemctl start qq-bot-postgres-backup.service
sudo systemctl status qq-bot-postgres-backup.service
sudo systemctl start qq-bot-postgres-restore-check.service
sudo systemctl status qq-bot-postgres-restore-check.service
cat /var/lib/qq-bot-postgres-backups/restore-check-latest.json
```

Tank 的结果位于
`/data/backup/postgresql/qq-bot-ha/restore-check-latest.json`。恢复检查使用独立临时
PGDATA 和 Unix socket，检查结束后删除，不会覆盖或停止生产 keeper 管理的数据目录。

当前是双节点物理复制加两份独立逻辑备份。完整 PITR 还需要第三个持久仓库保存
物理基础备份和连续 WAL；在该仓库确定前不能把同步 `archive_command` 指向 Tank
的 NFS，否则 Tank 离线可能让 h610 的 WAL 无上限堆积。

## 首次迁移顺序

1. 先在 h610 启动 monitor 和数据节点。Tank 当前离线时，h610 会成为临时主库。
2. `qq-bot-postgres-bootstrap` 创建低权限 `qq_bot` 角色、数据库、schema 和 pgvector。
3. 使用机器人仓库的 `qq-deepseek-bot-db upgrade` 创建 Alembic schema。
4. 从 `/var/lib/qq-deepseek-bot/state.pre-postgres-20260811` 执行 legacy dry-run、回填和一致性校验。
5. 保持机器人服务关闭，直到迁移检查全部通过。
6. Tank 恢复后部署同一份 Nix 配置，让它从 h610 做基础备份并进入 `secondary`。
7. 运行两台机器的健康检查，确认 h610 为主库、Tank 为 `secondary`。

## 恢复原则

- 不要同时手动启动数据目录里的 `postgres` 和 `pg_autoctl`；keeper 必须管理实例。
- 不要在未隔离旧节点时强制从 monitor 删除注册；顺序必须是先 fence、再移除。
- 不要在两台机器间用 `rsync` 复制正在运行的 PGDATA。
- 不要删除旧 5432 集群中的 `qq_bot` 数据库，直到新集群迁移、校验和备份都完成。
- 恢复优先使用已验证的 custom-format `pg_dump`；物理数据目录只由
  `pg_auto_failover` 的 base backup/rewind 流程处理。
