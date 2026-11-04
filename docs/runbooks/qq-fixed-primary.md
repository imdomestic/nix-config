# QQ PostgreSQL：固定主库与人工灾备

2026-11-04 owner 选择：tank 固定主库、h610 异步灾备。相关决策见 [qq-fixed-primary](../decisions.md#qq-fixed-primary)。这不是零停机/零丢失 HA：跨网复制可能积压，tank 真故障时需要人确认并切换。

## 正常状态

- `services.qq-bot-postgres-ha.failoverMode = "manual"`，两节点 `preferredNodeName = "tank"`。
- `qq-bot-postgres-node.service` 直接启动 PostgreSQL 17，**不运行 pg_autoctl keeper**；h610 的 monitor 服务关闭。
- 复用原 PGDATA、TLS、SCRAM、精确 tailnet HBA、隔离 Unix socket、WAL 容量上限、备份与恢复检查。主库 `synchronous_standby_names` 由命令行固定为空，h610 不阻塞 tank 写入。
- standby 的 `primary_conninfo` 和 `primary_slot_name` 由启动参数固定，密码只来自权限 0600 的 pgpass。启动准备不联系远端监控器、不 enroll、不 initdb、不自动移除 standby.signal、更不自动 promote。
- 原备库即使删掉 standby.signal，也会因 control-file recovery 状态被主库启动检查拒绝；缺少 signal 的备库同样拒绝启动。
- Gaoji DSN 只指向 tank，`target_session_attrs=read-write` 保留。更换主库必须同步改 DSN，不能偷偷退回原来的跨网多主候选列表。

## 只读检查

两边分别执行：

```sh
sudo qq-bot-postgres-health
sudo systemctl status qq-bot-postgres-node.service
sudo -u postgres psql -h /run/qq-bot-postgres-node -p 55432 -d postgres \
  -c 'SELECT pg_is_in_recovery();'
```

- tank 应为 `false`；h610 应为 `true`。
- tank 的 `pg_stat_replication` 应有 `application_name=qq_bot_standby`、`state=streaming`、`sync_state=async`；h610 的 WAL receiver 应连接 tank。
- health 每 30 秒检查实际角色、复制连接、最近回执及积压（默认 64 MiB）。异常返回失败并保留 `/run/qq-bot-postgres-health/health.json`，**只告警、不停止主库或提升备库**。其失败由现有 SystemdUnitFailed 告警覆盖。
- Gaoji 自身 `/health/qq-official` 的健康指标另外在 tank 和 h610 采集。当前不可用持续两分钟与历史 message_gap 是两条不同告警；Alertmanager 未配置外部接收器时只在界面显示，不声称通知已送达。

## 初次迁移（维护窗口）

1. 核对两节点真实角色、相同 system_identifier、复制进度、无活动 Bot 回合/任务，保存主库完整 PG17 归档并检查可读。保存两个数据目录的配置、pgpass、当前系统路径在各自 root-only 备份目录，不能提交到仓库。
2. 构建并 diff 两个新系统；确认固定角色、关闭 monitor、无 pg_autoctl ExecStart；评估与此次无关的共享主线漂移。内核变化不得直接 switch。
3. 先停 Gaoji，并用临时 systemd ConditionPathExists 维护闸门防止系统切换时提前启动；暂停备份/健康/恢复检查 timer 和可能启动节点的相关作业。停 h610 monitor，再在两边用 `qq-bot-postgres-fence-local --confirm-fence` 停 keeper 并创建持久 FENCED 标记，确认没有遗留 keeper/PostgreSQL 进程。不要在 monitor 仍可能接管时先停 tank。
4. 激活新系统。数据库 unit 有 `restartIfChanged=false`，必须显式启动新定义；先确认加载的是直接 postgres 的新 unit，再解除 tank 的 FENCED 并启动、检查可写，运行新 bootstrap 建立 `qq_bot_standby` 物理槽，再解除 h610 隔离并启动，核对只读与复制来源。不能通过删除 signal“修复”启动拒绝。
5. 两边核对角色、复制/槽、健康/备份 timer。移除本次 Gaoji 临时维护闸门并 daemon-reload，恢复 Gaoji，确认实际新包、租约、网关、发送器；不中断真实任务来做演示。
6. 确认新槽 active 且旧 `pgautofailover_standby_*` 槽 inactive 后，可仅删除旧复制槽，避免旧槽永久保留 WAL。保留原 monitor 数据和旧配置供审计；不再让旧 keeper 启动。
7. 写回实测记录、系统路径、备份路径并推送。不得把构建或测试通过当作已经迁移。

## 真正故障时人工切主

**绝不能因为 ping 不通就提升 h610。** 异步复制在不可恢复故障时可能丢最后一段写入。

1. 停止 Gaoji 写入，核对现有主库和候选库的 WAL、时间线、system_identifier，备份可读数据。记录可能丢失的尾部范围并取得 owner 的明确接受。
2. 必须先隔离旧主库：能登录 tank 时运行 `sudo qq-bot-postgres-fence-local --confirm-fence`，确认持久 `FENCED` 标记、服务停止和端口关闭；不能登录时必须通过可信带外手段断电/隔离写入。**无法证明隔离则停止，不提升备库。** 不把远端超时当作证明。
3. 两节点持久配置的 `preferredNodeName` 改为新主库，客户端 DSN 改为新主库；旧主库保持 FENCED。备库仍运行且只读时，人工核对后才能执行 PostgreSQL `pg_promote`；配置激活本身不能隐式提升。
4. 验证只有一个可写节点，再启动 Gaoji。新主库不要在未改好持久角色前重启（备库启动保护会拒绝缺少 signal 的目录）。
5. 旧主库回归不能直接启动：保持 FENCED，使用核对过的新主库做 `pg_rewind` 或保留旧 PGDATA 后重新 base backup，明确配置 standby.signal/上游，先验证新配置为 standby 再解除隔离。自动模式的 enroll/rejoin/prefer 工具不适用于此模式。
6. 切回 tank 同样先暂停写入、追平、隔离旧主、受控提升、同步改持久配置和 DSN，不允许两边各自保留可写历史。

## 回滚边界

- Bot 租约恢复补丁无迁移，可独立回滚应用包；不需要恢复数据库。
- 数据库管理方式不能盲目切旧 Nix generation：旧 generation 会重新启用 monitor/keeper，遗留 HA 状态可能触发不期望的降级或提升。
- 出现迁移问题时先保持 monitor 和 keeper 停止、Gaoji 停写；优先在已经核验的唯一主库上恢复固定角色 PostgreSQL。需要恢复自动 HA 时，必须重新核对实际角色/时间线与 monitor 状态，再按受控 enroll/rejoin 流程恢复，不能同时启动旧控制器。

## 隔离测试

`scripts/test-qq-bot-postgres-manual.py` 在非 postgres 的非 root 账号下使用两个临时 PostgreSQL；推荐以 systemd PrivateNetwork/PrivateTmp 运行。实测覆盖复制中断、主库停机超过旧分区超时、角色不自动变化、连接恢复追平、启动护栏和两库重启。测试不会连接生产端口，不依赖真实 QQ 或运营商链路。
