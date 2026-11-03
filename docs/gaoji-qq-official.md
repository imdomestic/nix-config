# Gaoji 官方 QQ 接入

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
