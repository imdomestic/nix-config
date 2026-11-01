# Gaoji 官方 QQ 接入

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
