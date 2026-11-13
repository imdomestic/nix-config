# Gaoji 官方 QQ 接入

## 2026-11-13 · Python 已完成功能发布到 tank

- owner要求暂停未完成功能、收尾提交并只部署tank。Bot PR #74合并为`ad5a6e1612798c93212b08f138f0f09946b81905`，Nix配置`f874a2a9`固定该版本；未部署/重启h610，未改主备关系、内核或Home Manager。F9四维费用页/每日预算、F7/F10/F8不在本次发布内。
- 发布阻碍已修复：`fe00a25`移除模拟VM测试对宿主QEMU的无意依赖；`55011b7`用确定性RED修复600秒审批在来源/配置检查间到期的终态误分类，并阻止回执检查后刚到期的批准领取执行。不放宽owner、原任务/租约或通知回执门槛。
- 最终固定本机快照全套1,971项、0失败、10跳过（1,432.751秒、exit0）；PR Linux CI与合并后Linux CI均1,971项通过，Nix包和Secret scan通过。UI构建与五项React检查通过，20个NixOS配置求值与lint通过。Windows credential ACL是已有失败，未修复也不声称全部CI绿色。
- tank上以hank隔离检出共享main，限制`max-jobs=2 / cores=4`实际构建。新旧内核均`linux-6.18.62`且路径相同；系统闭包差异仅gaojibot。dry-activate列出应用和accounts-daemon启停、polkit重启/dbus重载，未重启数据库、VM、Worker或Maxx。已有greeter UID和停用channels警告未顺带改动。
- 先用PG17在线备份，在systemd PrivateNetwork内实际恢复并执行`0077→0095`，10510条消息保持不变；再停旧应用、保留维护闸门，做最终完整备份并正式迁移。最终备份`/data/services/gaoji/backups/python-next-20261113/before-switch/qq_bot.dump`为96,266,512字节、0600，pg_restore目录检查通过；配置、checksum、schema/服务和健康证据均留在该root-only目录，未下载或提交凭据。
- 17:54:06 UTC（11-14 01:54:06 HKT）新版启动，Gaoji PID1720188。运行/启动profile均`/nix/store/946mbv9mzc2azz55p6jrnalcfiaxq3a3-nixos-system-tank-26.05.20261108.ac588ef`，包`/nix/store/yd2nw8hyrpdylg8gphg8027yb56br8cj-gaojibot-0.20.0`；12个运行源码SHA256与合并提交相同。QQ三次连续`ready / healthy=true / message_gap=false`，后续复查仍ready。
- tank数据库PID3417、VM服务PID3692101、Worker PID3255、Maxx PID340030均与切换前备份一致；schema为`0095_billing_source_metadata`，消息仍10510条。tank SQL可写，h610维持`qq_bot_standby / streaming / async`，没有启动keeper/monitor或自动切主。
- 收尾脚本曾因root PATH没有python3不能解析成功健康JSON，改用包引用的gaoji-env Python完成验证；这是检查脚本失败，未回滚或重复迁移，维护gate已移除。旧离线会话VM共有3个，活跃会话VM为0；未为刷新擅自开机、改依赖或删除/work/浏览器profile，后续复用须先执行显式工具升级。
- 边界：没有伪造真实QQ消息、请求实际模型、登录真实账号或执行真实运维操作；ready、包级校验和隔离备份演练不等于所有新功能端到端验收。数据库已有新增证据后不可仅切旧应用包；恢复旧版必须停写并恢复最终DB/config备份与仍固定tank主库的匹配系统，不能恢复旧HA控制器。

## 2026-11-04 · 固定 tank 主库与 QQ 租约自动恢复已部署

**当前策略：tank 固定主库、h610 异步只读灾备，故障由人确认后切换。下文历史记录中的 monitor、优先级、`qq-bot-postgres-prefer-tank` 不再适用于当前部署。** 人工切换、隔离与回滚边界见 [固定主库 runbook](runbooks/qq-fixed-primary.md)，取舍见 [决策](decisions.md#qq-fixed-primary)。

- owner 明确授权切回 tank、修复反复掉线，并选择不再跨网自动接管。Bot PR #73 合并为 `d39d0403115d2a19aa4cb18713d38ec28efd3c77`；运行期失租约或临时数据库异常先排空旧资源，再退避重获租约。暂停/禁用/永久配置错误不被自动越过，不抢其他实例的锁。历史消息缺口独立警告，不再把已经 ready 的网关报成离线。
- 应用全量运行 1,413 项测试，10 项跳过，零失败；隔离测试连续三次终止真实测试库租约连接（一次旧会话失效）后仍可收发。PR 与合并后的 Python、Nix、密钥扫描通过；Windows ACL 仍是既有失败，未混入修复。另用两个私有网络内的 PostgreSQL 演练复制中断 25 秒、主库停机超过旧分区阈值、角色不自动变化、恢复追平及启动护栏。
- 配置 `18f7dbea` 关闭 keeper/monitor、固定启动角色、DSN 仅指向 tank；`9410a51f` 修复生成 bootstrap 的缩进并添加构建期 Python 编译检查；`2674f165` 将 QQ 告警改为独立规则文件。lint、20 个 NixOS 配置求值及两台系统构建通过，内核不变。部署现场曾因生成脚本缩进失败暂停在安全单主状态，修好并实际执行 bootstrap 后才继续恢复备库与 Bot，没有忽略失败。
- 迁移前旧 HA 于 **21:17:46 HKT** 再次判 tank 不健康，h610 接管到 timeline 29；tank 的 `pg_rewind` 在跨网坏链路上长时间缓慢推进。重新备份当前 h610 主库，保存原 tank 目录，再用完整、逐块及整包 SHA-256 校验、`pg_verifybackup` 通过的物理副本恢复只读 tank。SSH 临时经 gizmo 流式中转，未修改路由、未在 gizmo 落盘数据库内容。
- 恢复的 tank 两次确认 replay 差 0、system_identifier 一致后，停 h610 monitor、控制服务和数据库，并保留持久 FENCED。h610 干净关闭的 checkpoint `2A/C7037E50` 已被 tank 回放至 `2A/C7037EC8` 后才提升；tank 进入 timeline 30。随后以直接 PostgreSQL 17.11 的 systemd unit 启动两边，h610 明确 `standby.signal` 并连接 tank 的 `qq_bot_standby` 物理槽。没有在部分 rewind 目录上强行提升，也没有同时启用新旧控制器。
- **22:43:54 HKT** 恢复新版 Gaoji，22:44 连续三次 `200 / ready`，23 时后复查仍正常。tank 实际可写，h610 只读并从 tank timeline 30 streaming / async；两边健康检查及复制差 0 验证通过。两个正常 unit 的 ExecStart 均为直接 `postgres`，无 pg_autoctl 进程，h610 monitor unit 已不存在，55431 不监听。
- 运行包 `/nix/store/wnjq1z5004dbnp032z512270yi2fn9ng-gaojibot-0.20.0`，四个修复文件 SHA-256 与合并源码相同；一个实际 QQ 租约会话，数据库仍为 `0077_retired_features`。没有主动中断真实账号租约或伪造真实 QQ 消息来验收，隔离恢复测试不能替代腾讯端到端实聊。
- 最终 tank 系统/启动 profile 均为 `/nix/store/bi6k8x1ccrcl4gm5s4xhfkyh5m58dsnr-nixos-system-tank-26.05.20261020.cd4ea8d`；h610 均为 `/nix/store/9qm828dm8zw5s7prgrx1dpzhb0ka5r3p-nixos-system-h610-26.05.20261020.cd4ea8d`。本次明确重启数据库、Gaoji、控制服务和监控；VM PID 2640955、Worker PID 4034763、Maxx PID 2392179 保持不变。最后的告警修正 dry-run 只重启两边 Prometheus，复查 Bot 和数据库 PID 均不变。
- QQ 不可用、指标无法采集、历史消息缺口三条规则实际从两边 `/api/v1/rules` 读取为 `health=ok`，不是只看配置存在。`scripts/test-gaoji-alerts.py` 的五类合成指标场景经 promtool 通过。Alertmanager 尚无外部通知接收器，此处只保证监测与规则生效，不声称已向人发送告警。旧 `extraRules` 多 JSON 拼接导致其他既有组未加载的问题未在此轮全局修改。
- h610 切换前逻辑备份 `/var/lib/qq-bot-postgres-backups/fixed-primary-20261104/qq_bot-before-fixed-primary.dump`（95,434,054 字节，0600）；同目录 `physical/` 保存压缩物理备份（base.tar.gz 223,346,547 字节）和 manifest。tank 上对应物理备份在 `/data/backup/postgresql/qq-bot-ha/fixed-primary-20261104/physical/`；旧未完成 rewind 目录保留为 `/data/lib/qq-bot-postgres-ha/17.pre-manual-20261104-partial-rewind`，**不可当作可启动备份**。两机 root-only `/root/gaoji-fixed-primary-20261104/` 保留迁移前配置与证据，不提交凭据。
- 22:48–22:49 在新主库另做 `qq_bot-20261104T144825Z.dump`（93,771,882 字节），并实际恢复至隔离 PostgreSQL；`qq-bot-postgres-restore-check.service` 验证 revision 0077 成功。备份、恢复检查、健康检查 timers 均 active。
- 正式配置检出已同步：tank 的 `/home/hank/.config/nix-config`、`/home/kenneth/.config/nix-config` 及 h610 的 `/home/hank/.config/nix-config`。另发现 tank `/home/kenneth/services/nix-config` 停在 `1c5f84aa`，与共享 main 大幅分叉（非 shallow）；仅安全尝试 fast-forward，失败后保留原提交，未强行 reset/rebase。该旧目录不可用于当前部署，未来仍须按 AGENTS.md 核对远端和实际系统闭包。
- 边界：运营商丢包未被“修好”，只是 Bot 主数据库不再依赖这条跨网路径；h610 复制/控制/向量服务仍可能受影响。异步灾备不是零 RPO，tank 真故障需要人工隔离和切换。先前自动接管的未同步尾部与停机期间 QQ 消息不能仅凭当前追平宣称已补回，重要请求应重发；禁止盲目回滚到会恢复旧 HA 控制器的 generation。

## 2026-11-04 · 后台任务续接修复已部署

- PR #72 以 merge commit 合并，Bot 固定到 `130e7f232b02aa59422522ed6e0a9dca825911fe`，部署配置 `c893d090`。前台每轮获取当前会话、当前用户的任务快照；追问查状态、补充向原任务插话，已有活动任务默认拒绝重复新建，明确独立工作才允许并行。没有新增迁移，数据库仍为 `0077_retired_features`。
- 20 个 NixOS 配置求值、lint、构建通过；内核不变。运行系统落后于共享主线的 Maxx 意图判断配置（`72a23b31`），dry-activate 明确会同时重启 Maxx。owner 追加授权后，03:15:38–03:15:47 HKT 正式切换，只重启 Gaoji / Maxx 各一次；数据库节点、Gaoji VM 和 Worker 的 PID 与启动时间不变，未手动激活 Home Manager。
- 部署前 QQ 已再次为 `503 / lease_unavailable`，monitor 与两节点 SQL 均确认 **h610 primary、tank secondary**。发布未切换主备、未调整优先级或复制策略：tank priority=100 / quorum=true，h610 priority=50 / quorum=false。03:16 验收时 tank 从 h610 streaming，回放差为 0；这是现场角色，不代表已恢复 tank 首选主库。
- 切换前确认无 queued/running 后台任务、无 prepared/executing QQ 回合。当前主库 h610 的 PostgreSQL 17 完整备份在 `/var/lib/qq-bot-postgres-backups/followups-20261103T174801Z/`：归档 95,812,103 字节、0600，目录检查可读（非恢复演练）。tank 的 runtime.env、原系统与启动 profile 路径保存在 `/data/services/gaoji/backups/followups-20261103T174801Z/`，均未下载到本地或提交仓库。
- 新包 `/nix/store/rk46jxs9b31266h6rdj4s3x8v64iv6zs-gaojibot-0.20.0`；运行系统与启动 profile 均为 `/nix/store/zm4lhv5z2mfm4326vcgy3cwcn8x69rn5-nixos-system-tank-26.05.20261020.cd4ea8d`，与已推送配置求值一致。原运行系统为 `/nix/store/cndn0j2lx59w648q7g9rx0h8wi89zv3m-nixos-system-tank-26.05.20261020.cd4ea8d`，原启动 profile 是其 deploy-rs activatable 包装，未执行回滚。
- QQ 连续三次 `200 / ready`，之后复查仍 ready，主库有一个官方租约会话；Maxx 网关 `resumed=true`。七个变更的运行文件 SHA-256 与合并提交一致；使用部署包的真实 Python 环境、假任务数据且无 DB/网络/凭据执行检查，确认默认防重复、独立任务参数、任务快照和数据转义规则生效。未向真实 QQ 注入测试消息，不能以此代替真实模型“做网页 → 查进度 → 加按钮 → 独立新任务”对话验收。
- PR 与合并后的 Python / Nix / 密钥扫描 CI 均通过；Windows credential ACL 仍为主线已知失败，未混入修复。QQ 故障后自动重获租约、HA 链路波动以及并行任务产物强制隔离仍未解决，本次仅随部署恢复了 QQ。

## 2026-11-03 · 故障接管后恢复 QQ 与 tank 主库

- 11-02 21:23 HKT monitor 再次判定 tank 不健康并提升 h610；QQ 在数据库错误后暂停，次日仍为 503 / lease_unavailable。数据库池已恢复不代表 QQ 租约会自行恢复。
- owner 授权恢复 QQ 并切回 tank。先在 h610 保存 `/var/lib/qq-bot-postgres-backups/qq-outage-failback-20261103T114936Z/`，归档 95,736,482 字节、0600，pg_restore 目录检查通过；tank 连续两次回放延迟为 0 后，19:50:22–19:51:21 执行一次 `qq-bot-postgres-prefer-tank`。
- 最终 monitor 与两节点 SQL 均确认 tank primary / 可写、h610 secondary / 只读并从 tank streaming。h610 保持 `replication-quorum=false`，仍是临时异步复制；本次未修改策略或优先级。
- 19:52 第一次重启 Gaoji 已取回租约。腾讯拒绝旧 checkpoint（4006），随后新 Identify 在 19:52:08 得到 READY；但进程内的历史 `message_gap` 标记令健康仍报 gateway_unavailable，不能误判为网关一直未连接。
- 确认无活动后台任务、无执行中回合且新 READY 已持久化后，20:15:51 再重启一次，仅续接新 checkpoint；20:16 起连续检查均为 ready，账号 advisory lock 有效。没有修改业务代码、数据库 schema、系统闭包或消息记录，也未主动向真实群发送测试消息。
- 旧会话中断期间的消息不保证补齐，重要请求需要重发。自动重获租约和历史缺口与当前健康状态的区分仍待单独修复；详情见 [事故记录](incidents.md#gaoji-qq-lease-outage-20261103)。

## 2026-11-02 · tank 首选主库已受控恢复

- owner 确认 tank 应为主库并授权立即切回。01:03:16–01:03:22 HKT 在 h610 执行一次 `qq-bot-postgres-prefer-tank`，返回 0；monitor 与两节点实际 SQL 均确认 tank 为 primary / 可写，h610 为 secondary / 只读。
- h610 保留此前临时的 `replication-quorum=false`，未恢复同步要求。tank 的 `synchronous_standby_names` 为空，h610 为 streaming / async 副本；切换前连续两次复制延迟为 0，切换后也多次追平，持续写入采样可出现几十字节瞬时差。
- 当前 h610 主库的切换前备份在 `/var/lib/qq-bot-postgres-backups/tank-failback-20261101T170122Z/`，PostgreSQL 17 归档 95,544,784 字节、权限 0600，pg_restore 目录检查通过。
- 切换后 QQ 旧账号租约失效，健康接口短暂为 503 / lease_unavailable。确认没有活动后台任务后，仅在 01:06 HKT 重启 Gaoji 获取新租约；之后三次健康检查均为 ready，tank 上有应用连接和有效账号 advisory lock。未发真实群消息验收。
- Bot 仍为 `9bb6c4b`，系统闭包未变，数据库仍为 `0077_retired_features`；未修改 Bot 代码、主备优先级或网络配置。自动接管原因及验收详情见 [事故记录](incidents.md#gaoji-tank-failback-20261102)。

## 2026-11-02 · 后台追加要求拒绝反馈已部署

- PR #70 已合并，Bot 固定到 `9bb6c4b4777e40e242d7d3f5abf4cf4298c45eac`；部署配置为 `9f75ce25`。只修复 Codex 拒绝追加要求后吞掉错误的问题，不修改凭据校验或 RPC 断线行为。
- 仅切换 tank 的 Gaoji：20 个 NixOS 配置求值通过，闭包差异只有 gaojibot，内核不变，dry-activate 仅列出 `gaoji.service` 停止/启动。未部署 h610 控制服务、未手工调整数据库角色，未激活 Home Manager。
- 该次发布时（上节受控切回之前），tank 是只读备库，WAL receiver 从 h610 接收 streaming 复制。发布前的 11-01 22:01–22:27 HKT 日志已显示 tank 为 secondary，keeper 从 10-25 起一直运行；该次 Bot 发布没有改变主备安排。tank 仍是配置与 owner 要求的首选主库，运行角色需实时核对，之后的受控恢复见上节。
- 切换前确认没有 queued/running 后台任务。用 PostgreSQL 17.11 从 tank 当前只读副本读取的完整备份位于 `/data/services/gaoji/backups/steer-rejection-20261101T160655Z/`，归档 95,545,448 字节、权限 0600，pg_restore 列出的归档目录可读。数据库仍为 `0077_retired_features`，本次没有新增迁移。
- 运行包为 `/nix/store/439pl8mcfgdk34hy03smbs7ni09ly121-gaojibot-0.20.0`；系统与启动 profile 均为 `/nix/store/7i8yp5q0ggwbl87v0i06xjgbfr7qcr9b-nixos-system-tank-26.05.20261020.cd4ea8d`。官方健康接口返回 `healthy=true / ready`，VM、数据库、Worker 和 Maxx 服务均 active。
- 在部署包的 Python 环境中，以本地假 RPC 答复验证拒绝会明确抛错；原有凭据代码与部署前逐字一致。未在真实群里人为触发 Codex 拒绝，也不把该包级检查当作客户端已收到失败通知。
- 回滚前系统为 `/nix/store/j956zgbmp4dn2wxsjymzi7i8wbggzbh1-nixos-system-tank-26.05.20261020.cd4ea8d`；本次未执行回滚或恢复数据库。两份 tank 配置 checkout 已同步到已推送的部署配置。

## 历史接入记录

2026-10-30：qq-bot 固定到 `9247fdc506eb00476e4a076e021e2112c8154fdd`，包含轻量化方案 S1–S8、发送器健康状态修正及前台进度提示要求。tank 运行 Bot 和会话 VM，PostgreSQL 主库保持在 tank，h610 运行配套控制服务。

每个官方会话复用工作区；空闲两小时停机，三十天未使用清理。全局允许八台运行中的沙盒，每个 owner 一台；导出上限 100 MiB。发布前使用服务用户及其 libvirt session 预装会话基础镜像，避免首次文件任务安装依赖。

本次发布采用全部代码完成后统一切换。先准备 tank/h610 闭包及数据库备份，再更新受保护的官方 host 配置、接入已授权的旧群时间线并激活新版。host 配置不提交身份或凭据；后台例行任务使用 gpt-6.1-sol，主动参与使用 gpt-6-luna。切换后检查实际连接、回合、文件上传与发送回执。

旧表保留。S9 只能在新版稳定一周并备份后执行。

2026-10-30 18:20 UTC 已完成统一功能切换，数据库升级到 `0072_qq_simple_binding`；群绑定、owner 关系和 10,119 条旧群历史均保留。切换前的完整备份在 tank 的 `/data/services/gaoji/backups/qq-s8-20261030T181848Z/`，目录 0700、备份 0600。tank 为主库，h610 为只读副本，切换没有更新内核或重启数据库。

真实会话 VM 已生成并导出 PDF；新版上传器向授权测试群发送进度和 PDF，腾讯均返回成功回执。该检查直接验证上传与消息接口，不代表用户已下载文件，也不代替新的群入站回合验收。默认 `gpt-6-luna` 和 `gpt-6.1-sol` 的实际 API 请求均成功，简单算式分别耗时 2.19 秒和 2.76 秒。首次上线发现健康接口仍读取旧发送器字段，PR #28 补齐运行状态，并以真实发送器启动、投递、停止回归验证。

18:49–18:51 UTC 的真实群文件任务端到端通过：前台使用 gpt-6-luna，复用会话 VM，生成 20,151 字节 PDF，文件与最终文字均主动发送并提交成功回执；用户确认能下载打开。回合耗时 89 秒。本轮模型未调用 say，PR #29 在官方前台系统提示中补回制作文件前先报进度的要求，并修正 NoneBot 日志显示 printf 占位符的问题。22 项现有进度与运行时检查通过；这不等同于新的真实回合已经验证了模型报进度。

2026-10-31：根据用户先前的退役授权及已确认的官方文件验收，关闭 Gaoji 的 OneBot 入口，移除 tank 的 NapCat、登录和健康检查服务配置，同时清理 h610 上已禁用的 Gaoji NapCat 配置和三条旧登录/在线检查告警。Gaoji 的部署不再引用 Max 的 `nix/napcat.nix` 或 `services.max.napcat`；历史、工作区及旧 NapCat 数据目录保留。确认 h610 的旧 Max 已禁用后，一并移除其闲置的 `inputs.max.nixosModules.max` 导入和根 flake 的旧 `max` 输入；tank 沿用共享仓库最新的 Rust Maxx 输入与配置。
