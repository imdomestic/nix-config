# QQ Bot PostgreSQL 高可用与容量设计

## 目标

机器人使用一套独立的 PostgreSQL 17 集群，不再依赖 Tank 上同时承载
Matrix、Minecraft 的 5432 集群。

- Tank 是首选数据节点，Tailscale 地址 `100.64.0.4:55432`。
- h610 是故障接管节点，Tailscale 地址 `100.64.0.3:55432`。
- Tank 离线的过渡期由 h610 运行 `pg_auto_failover` monitor，端口为 `55431`。
- 两个数据节点都在线时使用同步流复制。
- Tank 离线时，monitor 提升 h610；连接串会自动选择当前可写节点。
- Tank 恢复后先作为副本追平，再进行受控切回，不自动来回切换。

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
状态，几乎不消耗磁盘；14T 与 1T 的容量差异不会影响它。当前 Tank 离线，因此先
把 monitor 放在 h610 上完成迁移。这个过渡形态能防止双主，但不是完整三节点 HA：
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

Tank 的保护参数：

- 复制槽最多保留约 `32GB` WAL
- 逻辑备份最多保留 30 份、30 天
- 做备份后必须仍能预留至少 `200GB` 空间

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
```

查看服务日志：

```bash
systemctl status qq-bot-postgres-monitor
systemctl status qq-bot-postgres-node
journalctl -u qq-bot-postgres-node -n 100 --no-pager
```

Tank 恢复并显示为健康的 `secondary` 后，安全切回 Tank：

```bash
sudo qq-bot-postgres-prefer-tank
```

该命令会先检查 Tank 是否在线、同步完成且状态新鲜；条件不满足时会拒绝切换。
不要为了“看起来主库应该在 Tank”而强制改 PostgreSQL recovery 文件。

手动验证逻辑备份：

```bash
sudo systemctl start qq-bot-postgres-backup.service
sudo systemctl status qq-bot-postgres-backup.service
```

## 首次迁移顺序

1. 先在 h610 启动 monitor 和数据节点。Tank 当前离线时，h610 会成为临时主库。
2. `qq-bot-postgres-bootstrap` 创建低权限 `qq_bot` 角色、数据库、schema 和 pgvector。
3. 使用机器人仓库的 `qq-deepseek-bot-db upgrade` 创建 Alembic schema。
4. 从 `/var/lib/qq-deepseek-bot/state.pre-postgres-20260811` 执行 legacy dry-run、回填和一致性校验。
5. 保持机器人服务关闭，直到迁移检查全部通过。
6. Tank 恢复后部署同一份 Nix 配置，让它从 h610 做基础备份并进入 `secondary`。
7. 运行 `sudo qq-bot-postgres-prefer-tank`，再确认 Tank 为 `primary`、h610 为 `secondary`。

## 恢复原则

- 不要同时手动启动数据目录里的 `postgres` 和 `pg_autoctl`；keeper 必须管理实例。
- 不要在两台机器间用 `rsync` 复制正在运行的 PGDATA。
- 不要删除旧 5432 集群中的 `qq_bot` 数据库，直到新集群迁移、校验和备份都完成。
- 恢复优先使用已验证的 custom-format `pg_dump`；物理数据目录只由
  `pg_auto_failover` 的 base backup/rewind 流程处理。
