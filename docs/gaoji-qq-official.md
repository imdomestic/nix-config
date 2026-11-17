# Gaoji 官方 QQ 接入

## 2026-11-17 · 删除 Debian KVM 后端与 Codex 引擎（A4）发布到 tank 并完成真机复验

- **Bot 合并（`ed216a7`）**：
  - A4-1：PR #163（`+830 / -2,188`，将上层会话工作区生命周期抽为 `container_sandbox.py` 中的 `WorkspaceSandboxManager`，删除 `vm_sandbox.py`、`sandbox_tools_setup.py`、`src/sandbox_runtime/vm_network.py`、`tools/migrate_vm_workspaces.sh`、`tools/vm_smoke.py`、`tools/vm_manager_smoke.py` 及 `gaoji-vm` / `gaoji-ops-vm` 单元，`sandbox.backend` 固定为 `"container"`，净减 `1,358` 行）。
  - A4-2：PR #164（`+208 / -694`，模型链与常量迁入 `pi_engine.py`，删除 `codex_engine.py`、`sandbox_codex_bridge.py` 与 `AI_BACKGROUND_ENGINE` 开关，`CodexGateway` 改名为 `JobGateway`，后台固定为 `PiEngine`，同步更新 `README*`、SVG 架构图与技能说明，净减 `486` 行）。
  - 另含 T10 文件链路重写（PR #162）与容器内 `ssh_config` 普通文件修复（PR #159，`0644` 关闭 `systemd-ssh-proxy`）。
- **tank 切换**：配置 `de6cc917` 移除 `hosts/tank/gaoji.nix` 中已废弃的 `sandbox.vmImage` 与 `AI_BACKGROUND_ENGINE` 并固定 `qq-bot`。隔离构建内核保持 `/nix/store/ppm8487552xic16bdqzq9792px66ra37-linux-6.18.63/bzImage` 不变，闭包仅变更 `gaojibot`（`-181.4 KiB`）与 `gaoji-ops-guest-resolv.conf`，切换前确认在途回合为 `0`。原系统 `/nix/store/62kpycx70ifxjsbhga7q5qjbpiawz4if-nixos-system-tank-26.05.20261113.f1e5c35`，现系统 `/nix/store/zvhbkxqbkfyzwl8sna88919zibcgav2v-nixos-system-tank-26.05.20261113.f1e5c35`；`gaoji` PID `2920468`，`gaoji-vm.service` 与 `gaoji-ops-vm.service` 均为 `not-found`，`/health/qq-official` 连续三次 `ready / healthy=true / message_gap=false`（切换中观察到 `gaoji-ops-network.service` 因默认 `After=basic.target` 与 `sockets.target` 下的 `gaoji-ops-relay-*.socket` 产生一次依赖环告警，服务本身全部正常启动，已在 Bot PR #166 补加 `DefaultDependencies = false` 消除）。
- **h610 Headscale 声明式修复**：配置 `bcdd886b` 将 `hosts/h610/system.nix` 的 `headscale 0.29.4` 显式覆盖为 `buildGo127Module = pkgs.buildGo126Module` 并登记于 `docs/incidents.md#h610-headscale-go127-mapresponse`；按 owner 指示保持 h610 当前稳定的临时 Go 1.26 drop-in 与 GC root，留待下次维护窗口 `boot` + 重启时一并清理。
- **tank 真机验收（第 10–17 条及运维 SSH）**：
  - 容器沙盒（第 10–13 条、大文件、隔离）：`uname -a`（NixOS `6.18.60`）与 `pi --version`（`1.5.0`）正常；`/work/hello.txt` 跨容器停启保留而 `/tmp` 重置；`gaoji-python` 生成正弦曲线 PNG 导出校验通过；`packages` 参数按预期拒绝并提示使用 `pip/npm/uv`；`12 MiB` 写入与 `15 MiB` 导出 SHA-256 一致；公网 HTTPS `200`、中继未授权 `401`、宿主与 tailnet 端口阻断全部符合预期。
  - 运维容器 SSH：在 `gaoji-ct-ops@` 容器内不带额外参数直接执行 `ssh tank 'whoami && sudo -n whoami && uptime'` 与 `ssh h610 'whoami && sudo -n whoami && uptime'`，均以 `gaoji` 免密登录并拿到 `root` 权限。
  - `PiEngine` + `JobGateway` 真实 `cliproxy` 验收（第 14–17 条）：真实 `pi 1.5.0` 经 `JobGateway` 调宿主 `history` 工具并生成 Markdown 文件、中途 `steer` 补充来源链接生效、运行中 `cancel` 中止并吊销任务 token、不存在模型链首项触发 HTTP 400 自动降级至 `gpt-6.1-sol` 并在报告末尾附上降级说明，全部实测通过；真实 QQ 测试群端到端聊天验收留给 owner。

## 2026-11-17 · 删常驻程序/后台命令/额度提醒（T7）与重写发送器及清理旧发件箱（T9）发布到 tank

- **Bot 合并（`8a1a45f`）**：
  - T7：PR #152（`+54 / -19`，解耦 `vm_api.py` 写权限为 `VMDenied` / `VMWriteAdmission`）、PR #157（`+972 / -6,049`，删除 19 个 `program_*.py`、`vm_program_state.py`、`sandbox_units.py`、`skills/programs.md`、`admin_api/programs.py` 及对应测试，提取精简版 `vm_http.py` 保留 `gaoji say / send-file`）、PR #158（`+56 / -2,516`，删除 `background_commands.py`、`command_*.py`、`sandbox_commands*.py`、`admin_api/background_commands.py`、`budget_notice*.py` 及对应测试，保留 `daily_budgets.py`、`/config`、`/status`），合计净减 `7,502` 行。
  - 容器 SSH 配置热修：PR #159（关闭容器内 `systemd-ssh-proxy`）。
  - T9：PR #160（`+119 / -66`，`rate_limit.py` 改为令牌桶限速 60/min 全局、20/min 单群；`sender.py` 对齐 S1 默认主动发送、`unknown -> allowed` 晋升、`40034105` 回退 5 分钟被动窗口、不可用立即失败不挂起 24 小时、移除本地每日 1000 条计数扫描、完善 `40034006`/`401`/`429`/Markdown 降级/`ambiguous` 错误处理）与 PR #161（`+364 / -1,039`，删除无调用方的 `protected_plans.py`、`protected_payload.py`、`delivery_configuration.py`、`send_ledger.py` 及旧测试），合计净减 `622` 行。
- **tank 切换与核验**：配置 `9d19b80e` 固定 `qq-bot`；隔离构建内核保持 `/nix/store/ppm8487552xic16bdqzq9792px66ra37-linux-6.18.63/bzImage` 不变，闭包体积减少（`gaojibot: -479.9 KiB`、`gaoji-sandbox: -29.5 KiB`），切换前确认 `active_exec = 0`、`active_jobs = 0`，`dry-activate` 仅停止/启动 `gaoji.service`。
- 原系统 `/nix/store/pk9l5cy26g81j63cc97b3dzhw81q98kk-nixos-system-tank-26.05.20261113.f1e5c35`，现系统 `/nix/store/62kpycx70ifxjsbhga7q5qjbpiawz4if-nixos-system-tank-26.05.20261113.f1e5c35`；`gaoji` PID `2874546`、`NRestarts=0`，`/health/qq-official` 连续三次 `ready / healthy=true / message_gap=false`，启动后无新错误日志，`deliveries` 无 `pending/sending` 或新增 `waiting_reply_window`。真实测试群端到端聊天、后台 `gaoji say / send-file`、`/config`、`/status` 验收待实测。

## 2026-11-17 · h610 升级（`boot` + 重启）、`gaojiops` 移交 `gaoji@` 及容器/模型降级修复发布到 tank

- **h610 升级与运维身份（A3）**：在 h610 以 `kenneth` 低负载预构建 `f060d02c`（Generation 604 `/nix/store/g7kk7l0l1ikinfr3lx6655hmb4530kkk-nixos-system-h610-26.05.20261113.f1e5c35`，内核 `6.18.57 → 6.18.63`）。挂载重启前后 15 分钟自动回滚保护与 `systemd-boot` oneshot 引导后执行 `switch-to-configuration boot` + `reboot`；约 5 分钟完成拨号与 DDNS 恢复，`pppd-telecom`、`headscale`、`tailscaled`、`dae`、`nginx`、`qq-bot-postgres-node`（`lag=0`）全部 `active`，创建 `gaoji` 账户（uid 1006），随即解除回滚定时器并将 Generation 604 设为默认启动项。清理 `headscale.service` 上残留的 `50-tokyo-cutover.conf` 临时覆盖以使声明式 `gaoji@imdomestic.com` 组策略生效；因 Headscale 0.29.4 无 `nodes move` 子命令，删除旧节点 53 并用 `gaoji@imdomestic.com` 一次性短效 preauthkey 将 `gaojiops` 重新登记到 `gaoji@imdomestic.com`（节点 55，仍为 `100.64.0.10`，`online`）。
- **tank 修复发布（#155、#156）**：Bot PR #155（补充识别真实 `cliproxy` 对不存在模型返回的 `400 model_not_found / unknown provider` 以触发模型链降级）与 PR #156（`gaoji-ct-ops@` 改为由 systemd 服务单元先进入 `/run/netns/gaoji-ops` 再运行 `--private-users=pick` 容器）合并至 `main`（`c3b3d12`），配置 `f4c23135` 固定并切换 tank 至 `/nix/store/pk9l5cy26g81j63cc97b3dzhw81q98kk-nixos-system-tank-26.05.20261113.f1e5c35`（`gaoji` PID `2817362`、`NRestarts=0`，`/health/qq-official` 连续三次 `ready`）。
- **真机复测**：真实 `cliproxy` 模型降级（`nonexistent-test-model-000 → gpt-6.1-sol`）与运行中任务 `cancel` 中止及吊销 token 均实测通过；`gaoji-ct-ops@` 容器启动成功，实测 `ssh` 时发现容器用户命名空间下 NixOS 26.05 默认 `ssh_config` 引用的 `/nix/store/.../20-systemd-ssh-proxy.conf` 属主映射为 `nobody` 被 OpenSSH 拒绝（已另开修复关闭容器内 `systemd-ssh-proxy`）。

## 2026-11-17 · 启用 `pi` 后台引擎与模型链降级（`AI_BACKGROUND_ENGINE=pi`）

- 配置 `d0f910c0` 在 `hosts/tank/gaoji.nix` 最后加载的 `gaoji-models.env` 中设置 `AI_BACKGROUND_ENGINE=pi`、`AI_BACKGROUND_MODELS=gpt-6.1-sol,gpt-6-astra,gpt-6-luna`、`AI_BACKGROUND_CONTEXT_WINDOW=200000`（D2、D3 由 owner 指定）。
- tank 隔离构建，内核保持 `linux-6.18.63` 不变，无包闭包新增，切换前无活跃回合或后台任务，`dry-activate` 仅停止/启动 `gaoji.service`。
- 原系统 `/nix/store/1mgs4nl8k1dmrpg1mzyzn9q2bircswsk-…`，现系统 `/nix/store/nwbhw0hgji9yascv1ia3hb8v3sgv4im9-nixos-system-tank-26.05.20261113.f1e5c35`，`gaoji` PID `2709803`、`NRestarts=0`；`/health/qq-official` 连续三次 `ready / healthy=true / message_gap=false`。
- 用运行包代码与进程实际环境核对生效配置：`engine=pi`、`chain=['gpt-6.1-sol', 'gpt-6-astra', 'gpt-6-luna']`、`effort=high`、`context_window=200000`、`upstream_provider=cliproxy (configured=True)`，数据库 `state_blobs` 无旧覆盖项。真实测试群验收（第 9 节第 14–17 条）由 owner 进行；如遇异常将 `AI_BACKGROUND_ENGINE` 改回 `codex` 即可一键回退。

## 2026-11-17 · pi 后台、模型链降级与 `/job` 工具路由（#147）合入并先按默认 Codex 发布到 tank

- Bot PR #147（中转 `/job/tools` 与 `/job/tool` 流式心跳路由、后台模型链按序降级与分次计费、`pi` 插件/RPC 桥接/`PiEngine` 及容器系统内置 `pi`，默认仍为 `AI_BACKGROUND_ENGINE=codex`）连同 #151、#152、#153 合入 `main`（`d8a83e6bbf7dac7443b4f9bbc997aaf39816d235`）。本机全套 1,821 项测试通过，`check_pi_job.py` 16 项全通，CI 5 项全绿。
- 配置 `72adb086` 固定 `qq-bot`；tank 隔离构建，内核保持 `linux-6.18.63` 不变，闭包差异仅 `gaojibot` 与 `gaoji-pi`，切换前无活跃回合或后台任务，`dry-activate` 仅停止/启动 `gaoji.service`。
- 原系统 `/nix/store/036rav9rxy3qh7vg64w7zgiaa1zjxm56-…`，现系统 `/nix/store/1mgs4nl8k1dmrpg1mzyzn9q2bircswsk-nixos-system-tank-26.05.20261113.f1e5c35`，`gaoji` PID `2693631`、`NRestarts=0`；`/health/qq-official` 连续三次 `ready / healthy=true / message_gap=false`，启动后无新错误。`AI_BACKGROUND_ENGINE=pi` 尚未开启。

## 2026-11-17 · 删跨群关联/跨群提问代码（T2）并删掉已无代码的 34 张旧表（T3）

- Bot PR #150（T2：删除跨群关联 `link_*.py`、`linking.py` 与跨群提问 `question_*.py`、`questions.py` 及调用点与测试，共 `-6,928 / +52` 行，保留库表待后续统一迁移删除）与 PR #149（T3：新增迁移 `0107_drop_dead_tables` 删除 `fleet_*`、`alert_*`、`diagnostic_*`、`ops_actions`、`ops_replies`、`host_api_calls`、`host_api_quota`、`admin_fleet_watches`、`turn_reaction_votes` 共 34 张无代码引用表，并清理 `reaction_feedback.py` 死文件，共 `+255 / -173` 行；降级仅重建空表结构、不恢复数据）各自本机隔离全套测试与 CI 5 项全绿后合并至 `main`（`1a01c37ea4434def273a4626fcd42cd9ed55260a`）。
- 切换前先在 tank 完成全库备份 `/data/services/gaoji/backups/pre-drop-dead-tables-20261117T1926Z/qq_bot.dump`（PostgreSQL 17.11 custom 格式，`99M`、`0600`、`1,086` 个归档条目，SHA256 `06d2c75cb44db0978a8dcc58c9ab5a4f4f70233dc892736355ff2f86f91aa821`），并确认无 `prepared/executing` 回合、无 `queued/running` 后台任务。
- 配置 `b3150c50` 固定 `qq-bot`；在 tank 隔离检出构建（`max-jobs=2 / cores=4`），内核保持 `/nix/store/ppm8487552xic16bdqzq9792px66ra37-linux-6.18.63/bzImage` 不变，闭包差异仅 `gaojibot`（`-496.8 KiB`），`dry-activate` 仅停止/启动 `gaoji.service`。
- 原系统 `/nix/store/4vp7n8kgays1a3lrkpbyg7jcysr13j67-nixos-system-tank-26.05.20261113.f1e5c35`，现系统 `/nix/store/036rav9rxy3qh7vg64w7zgiaa1zjxm56-nixos-system-tank-26.05.20261113.f1e5c35`，启动前自动执行 `0106_question_notices -> 0107_drop_dead_tables` 迁移，`gaoji-db check` 返回 `PostgreSQL ready: schema=qq_bot revision=0107_drop_dead_tables`；`gaoji` PID `2647617`、`NRestarts=0`，`/health/qq-official` 连续三次 `ready / healthy=true / message_gap=false`，启动后无新错误日志。未向真实群发送测试消息；真实测试群普通聊天、发文件、后台任务验收由 owner 进行。

## 2026-11-17 · 切换至 NixOS 容器沙盒（`sandbox.backend = "container"`）并迁移工作区

- 配置 `60673bf8` 在 `hosts/tank/gaoji.nix` 启用 `sandbox.backend = "container"`（保留 `vmImage` 以便一行回退）；owner 已确认 D6（`/nix/store` 无密钥）。预演时发现 `tools/migrate_vm_workspaces.sh` 需等待 `nbd` 异步识别分区并以 `ro,noload` 挂载曾断电旧盘（PR #153）；另合入 PR #151 为 `maintain_conversations` 补齐沙盒编号与错误文本日志。
- 切换步骤：确认无活跃回合/后台任务及无运行中 VM 后停止 `gaoji.service`；先只读预演再 `--apply` 将全部 22 个沙盒 `/workspace` 复制至 `/var/lib/gaoji-ct/<id>/work`（`1000:1000`，含三个活跃官方会话 `s26b4ac` 547M、`sc373ac` 519M、`s8100c4` 112M），旧 `qcow2` 磁盘全程只读未改动。
- 系统由 `/nix/store/999ablanyvkz08sxzfh9rwyv745na7jv-…` 切换至 `/nix/store/4vp7n8kgays1a3lrkpbyg7jcysr13j67-nixos-system-tank-26.05.20261113.f1e5c35`（内核保持 `linux-6.18.63` 不变，停掉 `gaoji-vm` / `gaoji-ops-vm`）。
- 宿主核验：网桥 `vz-gaoji` 为 `10.0.2.2/24`；`/run/gaoji-ct/broker.sock` 为 `kenneth:users 0600`；宿主与 `gaoji-ops` 命名空间 `10.0.2.2:18640/18641` 中继监听正常；`nft list table inet gaoji-ct` 已加载；进程环境 `AI_SANDBOX_BACKEND=container`，`gaoji` PID `2583710`、`NRestarts=0`，`/health/qq-official` 连续三次 `ready / healthy=true / message_gap=false`。真实群聊/运维会话验收（第 9 节第 10–12 条、>10 MiB 文件、`ssh tank uptime`、迁移旧文件检查）由 owner 进行。

## 2026-11-17 · 容器沙盒代码（#146）合入并先按默认 VM 模式发布到 tank

- Bot PR #146（新增 NixOS 容器沙盒后端 `sandbox.backend = "container"`、`gaoji-ct-broker`、隔离网桥与 nftables、工作区迁移脚本与手册，默认仍为 `vm`）基于 `d593f89` rebase 后本机隔离全套 2,009 项测试通过、CI 5 项全绿，合并至 `main`（`bb1320503387e20c41a08fd2f841dead2ea54236`）。
- 配置 `0eb10d93` 固定 `qq-bot`，先保持 `sandbox.backend = "vm"` 验证线上无回归；tank 隔离构建，内核保持 `linux-6.18.63` 不变，闭包差异仅 `gaojibot`（+30.1 KiB），切换前无运行中回合或后台任务，`dry-activate` 仅重启 `gaoji-ops-network.service` 与 `gaoji.service`。
- 原系统 `/nix/store/kswk9fkvzs9yrzysjd2gwrgkfkwy1nhk-nixos-system-tank-26.05.20261113.f1e5c35`，现系统 `/nix/store/999ablanyvkz08sxzfh9rwyv745na7jv-nixos-system-tank-26.05.20261113.f1e5c35`，`gaoji` PID `2500265`、`NRestarts=0`；`/health/qq-official` 连续三次 `ready / healthy=true / message_gap=false`，启动后无新错误。容器后端尚未启用。

## 2026-11-17 · A 阶段热修、D2 网页抓取后备及 A0 空回答去重发布到 tank

- Bot PR #133（大文件分块导出、QGA 通道损坏自动重启 VM）、#139（来源仅列回答引用的编号、清理跟踪参数）、#140（工具已发出内容时空回答不算失败）、#141（跳过被拦的 DuckDuckGo、过滤无关结果）、#142（提示词收紧搜索原词、直开链接、视频区分、找图路由、文字不说"听错"）、#143（后台报告首行写明成败、后台能读 `use_skill`）、#144（预算竞态测试修复）、#145（D2 网页被拦换浏览器请求头重试并回退搜索摘要）及 #148（A0 删除 `platform_chat.py` 冲突合并残留的 13 行重复空回答检查）全部合并至 `main`（`d593f8967da59397b3e1f5f46006929a268fea79`）。整合树本机全套 2,001 项通过，#148 CI 5 项全绿。无数据库迁移。
- 配置 `d1791760` 固定 `qq-bot`；在 tank 以 `kenneth` 隔离检出构建（`max-jobs=2 / cores=4`），内核保持 `/nix/store/ppm8487552xic16bdqzq9792px66ra37-linux-6.18.63/bzImage` 不变，闭包差异仅 `gaojibot`（+87.5 KiB），`dry-activate` 仅停止/启动 `gaoji.service`（及重载 `systemd-networkd`），切换前确认无 `prepared/executing` 回合、无 `queued/running` 后台任务。
- 原系统 `/nix/store/lwj1by13xbh5h3r68wdh0k5xxd16vvl7-nixos-system-tank-26.05.20261113.f1e5c35`，现系统 `/nix/store/kswk9fkvzs9yrzysjd2gwrgkfkwy1nhk-nixos-system-tank-26.05.20261113.f1e5c35`，`gaoji` PID `2390132`、`NRestarts=0`；`/health/qq-official` 连续三次 `ready / healthy=true / message_gap=false`，启动后无新错误日志。
- 未向真实群发送测试消息；真实 QQ 测试群按 `docs/nixos-vm-pi-plan.md` 第 9 节第 1–9 条对话验收由 owner 进行。

## 2026-11-17 · 自动运维上线；删掉未使用的集群、运维与 Docker 沙箱代码

- Bot PR #135–#138 合并（`main` 为 `f0014a7`），配置 `6fbba0fc`、`e73f3b7f` 固定：删除 QQ 探针、Docker 沙箱、gaoji 集群控制/worker/部署器/主机控制/SSH 运维、运维审批和宿主 API 代理（10-30 后未使用）；新增仿 Max 的自动运维。nix-config 同步撤掉 h610 的 cluster.nix、tank/h310 的 gaoji-worker、2224 端口 SSH、相关密钥、placement、监控与告警。
- 自动运维：tank 上 `gaoji-ops` 网络命名空间跑独立 Tailscale 节点 `gaojiops`（100.64.0.10）；owner 私聊和一个可信群的 VM 由命名空间里的第二个 libvirt（`gaoji-ops-vm`）启动，VM 内 `ssh <主机>` 以 `gaoji`（免密 sudo）登录，Tailscale SSH 认证，VM 不放密钥。中继端口 18640/18641 经命名空间内 socket 转发回宿主。
- tank 切换：内核不变，`dry-activate` 停 gaoji-cluster-worker，重启 sshd/polkit，重载 nftables，重启 gaoji。现系统 `/nix/store/50achshyp32bx135imj6p57kgqhz0bvn-nixos-system-tank-26.05.20261113.f1e5c35`，`/health/qq-official` 连续三次 ready。从命名空间 `ssh gaoji@tank` 与 `sudo -n` 验证通过，公网可达。
- Headscale 已建用户 `gaoji@imdomestic.com`，但组成员需 h610 部署。h610 升级（10-20→11-13 nixpkgs）在 20:27 失败：tailscaled 被替换导致 Tailscale SSH 会话断开，`switch-to-configuration` 在逐个重载用户单元时遇到 hank 会话刚好消失（`Failed to get GID for hank` / `Unknown object .../user/_1000`）后退出，已停止的拨号等服务未重启，断网约 15 分钟，由预先设置的 15 分钟自动回滚恢复（新公网 IP，DDNS 已更新）。h610 仍为 `/nix/store/gy75xq1rz48nrjr15a239y381yk2abhv-…`。建议改用 `switch-to-configuration boot` 加重启升级 h610。
- 因此 `gaojiops` 暂登记在 `kenneth@imdomestic.com` 下；h610 升级后用 `headscale nodes move` 挪到 `gaoji@`。`gaoji` 账户目前只在 tank 存在，其他主机要各自部署后才有。
- 迁移这两个会话的 VM 时，群 VM 已关机；owner 私聊 VM 不响应 ACPI/agent 关机，最终强制断电。两者已从普通 libvirt 进程 undefine，下次使用在运维网络启动。真实群聊中的运维对话尚未验证。

## 2026-11-17 · 能看到群里其他机器人的消息；机器人之间适时停下

- 发现问题：QQ 对其他机器人的消息带 `author.bot=true`，编解码器将其记为 `bot_origin` 并跳过，不进账本；自 10-30 起共跳过 299 条（全部在同一群，仅 4 条与 gaoji 自己发送时间相近，且从未出现 gaoji 自身回声），因此 gaoji 看不到 Max 的发言。
- Bot PR #134（`main` 为 `3833e262299d445bdf615f4488eb30ecc7f66201`）：其他机器人的消息按普通群成员入账，名字标"（机器人）"，原始事件记 `sender_is_bot`；自身回声仍先被丢弃。提示词要求与机器人聊到没必要时收尾或 `[silence]`；另设硬上限：10 分钟内没有真人插话时，连续机器人消息最多被回复 3 次（直接触发和主动插话都适用）。本机编解码/入库 56 项测试通过；QQ 全套 675 项中 2 项端到端超时，单独重跑确认为改动前即存在的偶发超时。已跳过的旧消息正文已按保留策略清除，无法补回。
- 配置 `f9a72943` 固定；tank 隔离构建，内核不变，闭包差异仅 gaojibot；`dry-activate` 仅停止/启动 `gaoji.service`，切换前无运行中的回合。原系统 `/nix/store/503rn7akr5fzm19k6jwc8s275k900ayb-…`，现系统 `/nix/store/yz4842nj0agy6dsafx3am25rlivjpsdm-nixos-system-tank-26.05.20261113.f1e5c35`，`gaoji` PID `3907253`；`/health/qq-official` 连续三次 ready，启动后无新错误，运行包已含 `peer_bots.py` 与新提示词。

## 2026-11-17 · 修正：默认模型此前未真正切到 Gemini；主动插话也改用 Gemini

- 发现问题：`863ae7e8` 只改了 `AI_MODEL_DEFAULT_PROFILE`，但 `lib/gaoji-model-profiles.nix` 生成的 `AI_MODEL_PROFILES_JSON` 自带 `"default": "gpt-6.1-sol"`，其优先级更高；部署后 13 轮正式回答实际仍为 `gpt-6.1-sol`，当时只核对了环境变量、未核对生效模型。`e2c43d4f` 把内嵌默认改为 `gemini-3.8-flash-high` 并注明优先级。
- 主动插话分类器的模型在主机 `qq-official/host.json` 的 `native_background.proactive.profile`（不在仓库内）。owner 批准后由 root 备份为 `host.json.bak-20261117`，并把 `gpt-6-luna` 改为 `gemini-3.8-flash-high`，JSON 校验通过。
- 切换：`dry-activate` 仅停止/启动 `gaoji.service`，切换前无运行中的任务或回合。原系统 `/nix/store/kxsgsqv642nr7r0ja411y7c7w2m6asw7-…`，现系统 `/nix/store/503rn7akr5fzm19k6jwc8s275k900ayb-nixos-system-tank-26.05.20261113.f1e5c35`，`gaoji` PID `3109153`、`NRestarts=0`，`/health/qq-official` 连续三次 ready。
- 用运行包代码与进程实际环境/凭据核对：正式回答默认 `gemini-3.8-flash-high`（`reasoning_effort=high`、超时 180 秒），主动插话 `gemini-3.8-flash-high`。

## 2026-11-16 · Gemini 开启 high 思考；提示词分清闲聊与提问、提供情绪价值

- owner 认为回答不如 Max 详细。Max 使用同一 `gemini-3.8-flash-high` 但 `effort = "high"`；gaoji 此前不发送思考强度。`lib/gaoji-model-profiles.nix` 为该档位设置 `reasoning_effort = "high"`、超时 90→180 秒（`9492f53f`；其格式问题由 `b92ad8de` 修正，推送时漏检 lint）。
- Bot PR #131（先分清闲聊与提问：闲聊简短；提问先想清楚、结论在前、讲清理由、查证出处、不抖机灵）与 #132（有人难过或分享好事时先接住情绪）按 owner 要求未等 CI 合并，`main` 为 `0f3eb134f9403f09fa857cf76e07d86181fae7d3`；配置 `e93f7edc` 固定。
- tank 隔离构建，内核不变，`dry-activate` 仅停止/启动 `gaoji.service`，切换前无运行中的任务或回合。原系统 `/nix/store/08hzf2r063qkria2m4fydjxb8a7jaadg-…`，现系统 `/nix/store/kxsgsqv642nr7r0ja411y7c7w2m6asw7-nixos-system-tank-26.05.20261113.f1e5c35`，`gaoji` PID `3045735`、`NRestarts=0`；`/health/qq-official` 连续三次 ready，启动后无新错误。

## 2026-11-16 · 全局统一模型（Gemini 3.8 flash），只有 owner 能改

- 目的：成员各自 `/model` 让同一会话分散在多个模型上，三天内 luna / Gemini 输入缓存命中仅 54% / 51%。Bot PR #130：`/model` 设置全局模型且仅当前 owner 可改，其他人只读；`/model 群默认` 仍可单独设群；选择顺序为群默认 → 全局 → 配置默认；个人模型条目不再读取（未删除），推理强度仍按个人。按 owner 要求未等 CI 合并，`main` 为 `05d5ffcf1c1b167c4ed69ad0538e4d70cdb2640a`；本机相关 85 项测试通过。生产库中仅有 OneBot 时期的旧键，官方会话无群默认。
- 配置 `863ae7e8`：`AI_MODEL_DEFAULT_PROFILE` 由 `gpt-6.1-sol` 改为 `gemini-3.8-flash-high`，`AI_SIMPLE_CHAT_PROFILE` 置空（不再把闲聊分给 `gpt-6-luna`）。
- 闭包差异除 gaojibot 外含共享 main 上未部署的 `ollama 0.40.15 → 0.40.16`；`dry-activate` 另需重启 `ollama`、`accounts-daemon`，重启 `polkit`、重载 `dbus-broker`。owner 确认后一并切换；切换前发现运行系统已是他人部署的 `/nix/store/8qj7wmp37x3n1bcx6xqsmv5hnifvl8q7-…`，本次基于最新 main 构建，未回退其改动。
- 现系统 `/nix/store/08hzf2r063qkria2m4fydjxb8a7jaadg-nixos-system-tank-26.05.20261113.f1e5c35`，内核不变；`gaoji` PID `2980169`、`ollama` PID `2979647` 均 `NRestarts=0`，`maxx` 未重启；`/health/qq-official` 连续三次 ready，运行环境默认模型为 Gemini，启动后无新错误。

## 2026-11-16 · 表情入库规则改为"只排除截图和照片"；人设去掉"捏"

- owner 决定除截图和照片外都留在表情库：先手工恢复 Gemini 重打后停用的 13 张（`media_analysis` 置 `is_sticker=1 / safety=safe`、启用并重建向量；原值在 `20261116-retag` 备份内），库内 357 张启用，3 张（2 截图、1 照片）停用。
- Bot PR #129（打标签增加 `kind`，只有 `screenshot` / `photo` 不入库；表情检索与发送不再要求 `safety=safe`，以库内启用且未封禁为准）按 owner 要求未等 CI 即合并，`main` 为 `a143be2d5de464b4767ce86f96b5332b7bc08c2b`；合并后该 PR 的 CI 5 项均已通过。配置 `5a4907a7` 固定 `qq-bot`。
- owner 要求去掉句尾"捏"：备份后修改主机 `persona.md`（语气词示例去掉"捏"并写明不在句尾加"捏"）与 `style-examples.md`（"抱歉捏"→"抱歉"），备份在 `/data/services/gaoji/media-repair-backups/20261116-persona/`；两文件不在仓库内。
- tank 隔离构建，内核不变，`dry-activate` 仅停止/启动 `gaoji.service`，切换前无运行中的任务或回合。原系统 `/nix/store/81gkplbmxlk8mrvkiry8zahr90pf83a6-…`，现系统 `/nix/store/25lbqkgwyl23zja97z34afg7yfdkdacf-nixos-system-tank-26.05.20261113.f1e5c35`，`gaoji` PID `966475`、`NRestarts=0`；`/health/qq-official` 连续三次 ready，启动后无新错误。

## 2026-11-16 · 表情收录、近期去重、少引用发布到 tank；识图改用 Gemini

- Bot PR #126（同一会话 6 小时内发过的表情排后、语境合适时主动带表情）、#127（群聊/私聊收到的 QQ 收藏表情自动打标签入库，不受图片识别开关限制，全站每日上限 200；打标签提示词改为适中偏详细并包含口语情绪词）、#128（一轮回复只有第一条、且之后有人插话时才引用原消息）各自 CI 5 项通过后合并，`main` 为 `99674144e4acd51afefc5cab556bf4946485eb53`。无数据库迁移。三者合并后本机全量 2,361 项中仅 2 项因本机缺 `TEST_OPS_POSTGRES_DSN` / `AI_POSTGRES_DSN` 报错。
- 配置 `aca31e3a` 固定 `qq-bot`，并在最后加载的 `gaoji-models.env` 中设置 `AI_VISION_PROFILE=gemini-3.8-flash-high`，覆盖主机 `runtime.env` 中的 `gpt-5.6-luna`。未使用 Rewind：其仅支持 Responses 接口，gaoji 网关只支持 chat completions，且文档标注为有条件使用。
- 在 tank 以普通用户隔离检出构建；内核不变，`diff-closures` 仅 `gaojibot`（+13.7 KiB），`dry-activate` 仅停止/启动 `gaoji.service`；切换前无运行中的后台任务或回合。原系统 `/nix/store/mh8yvg0j15maqx3gnrgbxixj1mdjvr0j-nixos-system-tank-26.05.20261113.f1e5c35`，现系统 `/nix/store/81gkplbmxlk8mrvkiry8zahr90pf83a6-nixos-system-tank-26.05.20261113.f1e5c35`，`gaoji` PID `794981`、`NRestarts=0`，`/health/qq-official` 连续三次 `ready / healthy=true / message_gap=false`，运行环境 `AI_VISION_PROFILE=gemini-3.8-flash-high`。
- 重打标签（owner 批准）：先备份全部表情的 `media_analysis` 与 `sticker_library` 到 `/data/services/gaoji/media-repair-backups/20261116-retag/`，再为 360 张启用表情各排一条 `caption` 任务，由运行中的媒体 worker 用 Gemini 重写标签并重建向量。约 22 分钟内 360 条全部成功，向量 360 条全部重建；344 张仍启用且标签均为 `gemini-3.8-flash-high`，16 张因新判定停用（10 张 safety=review，2 张 blocked，4 张判为非表情或截图），可按备份或控制台审核恢复。
- 未向真实群发送测试消息；真实对话验收由 owner 进行。

## 2026-11-16 · 表情包发送与图片校验修复发布到 tank

- Bot PR #124（放宽 PNG/JPEG 校验：调色板/低高位深/隔行 PNG、SOF1/CMYK JPEG、结束标记后的多余字节、扫描中途截断的 JPEG）与 #125（表情校验失败不再变成无日志的“内部错误”、`find_stickers` 不再把结果标为已用、发送计数生效、发送结果带表情描述、检索拆词并加近义词组）各自 CI 5 项全部通过后合并，`main` 为 `849de336bad36a7371ae7b510aaa438aa99ef74f`。无数据库迁移。
- 部署前（owner 批准）修复生产表情库中 13 张校验失败的表情：本机重新编码后逐张通过线上校验，在一个事务内按旧哈希核对更新 `media_blobs` 的哈希/大小/路径（13 行），旧文件保留。行备份、旧文件与执行的 SQL 在 `/data/services/gaoji/media-repair-backups/20261116-stickers/`。
- 配置 `3f3bd70a` 固定 `qq-bot`。从 Mac 用 deploy-rs `--remote-build` 时 `nix copy --derivation` 停滞 36 分钟无进展，改为在 tank 上以普通用户在 `/tmp` 隔离检出构建（`max-jobs=2 / cores=4`）；系统 drv 与 Mac 求值一致（`h29sb3ll…`）。内核不变，`nix store diff-closures` 仅 `gaojibot`（+12.5 KiB），`dry-activate` 仅停止/启动 `gaoji.service`。
- 切换前无运行中的后台任务或回合。原系统 `/nix/store/qmcb2inri57l7fw9ci5s3y1jq0d32d83-nixos-system-tank-26.05.20261113.f1e5c35`，现系统 `/nix/store/mh8yvg0j15maqx3gnrgbxixj1mdjvr0j-nixos-system-tank-26.05.20261113.f1e5c35`（包 `/nix/store/v3k8izv53walkixid052yc4xf4964grf-gaojibot-0.20.0`），`gaoji` PID `622996`、`NRestarts=0`。`/health/qq-official` 连续三次 `ready / healthy=true / message_gap=false`，启动后无新增错误日志。
- 未向真实群发送测试消息；表情检索效果仅用 360 张生产表情标签离线比对验证，真实对话验收由 owner 在群里进行。回滚只需切回原系统路径；13 张表情的数据可按备份 CSV 改回。

## 2026-11-16 · Python F8/F9/F10 及 Windows ACL 修复发布到 tank

- Bot 汇总 PR #123（`42d9155`）合并至 `main`（`6b74445f755ece0d1e5fc64c35a7f5693cabefed`），并关闭堆叠草稿 PR #75–#122。本机固定快照 `summary-42d9155`（`2,339` 项、`10` 跳过、`1407.929s`、`exit 0`）、PR CI（`43743729498`）与 `main` 合并后 CI（`43746200082`）全部 5 项通过：其中 `Python 3.12` `2,339` 项通过（`1315.837s`、`10` 跳过），`Windows credential ACL` `15` 项原生 DACL 检查全部通过（`0.088s`），`Admin UI`、`Nix package`、`Secret scan` 通过。
- Nix 配置在 rebase 至 `origin/main`（`9254ff48`）后由 `7a05aabc` 将 `qq-bot` 固定至 `6b74445f755ece0d1e5fc64c35a7f5693cabefed`，19 个 NixOS 与 5 个 Darwin 主机配置求值均通过。仅部署 `tank` system，未操作 `h610`、主备关系、内核或 Home Manager。
- 切换前检查：`tank` 内核保持 `/nix/store/ppm8487552xic16bdqzq9792px66ra37-linux-6.18.63/bzImage` 不变；`nix store diff-closures` 仅显示 `gaojibot`（`983.4 KiB`）及来自 `origin/main`（`1493cdae`）的静态 `index-x86_64` / `index-x86_64-linux` 数据库更新（`10.3 MiB` / `54.1 KiB`）；`dry-activate` 仅涉及 `gaoji.service`、`accounts-daemon.service`、`dbus-broker.service` 与 `polkit.service`，未重启数据库、VM、Worker、Maxx 或其他业务服务。
- 先在在线备份 `/data/services/gaoji/backups/python-next-20261116/online/qq_bot.dump`（`93M`、`0600`、SHA256 `e83dafa526dafdc19ba86951f1201523f602d283e0669418530bec8387a95db6`）上通过 `systemd-run -p PrivateNetwork=yes` 完成隔离 `pg_restore` 与 `gaoji-db upgrade/check` 演练（`0095_billing_source_metadata → 0106_question_notices`、`10590` 条消息完整保留）。
- 随后停止 `gaoji.service` 并保留最终停写备份 `/data/services/gaoji/backups/python-next-20261116/before-switch/qq_bot.dump`（`93M`、`0600`、SHA256 `bf9b2c7705a5f5921af01cbcc039c2219aaa0b85034bb77f72c263e4af6cd924`），记录原系统路径 `/nix/store/1m06828syk4irf85jkdnphs621rn22a6-nixos-system-tank-26.05.20261113.f1e5c35`。
- 切换至 `/nix/store/qmcb2inri57l7fw9ci5s3y1jq0d32d83-nixos-system-tank-26.05.20261113.f1e5c35`（应用包 `/nix/store/ab5v0blw54kddn46pg94gi2wisfms2a4-gaojibot-0.20.0`），启动前自动完成 `0095_billing_source_metadata → 0106_question_notices` 迁移，`messages` 仍为 `10590` 条，`gaoji` PID `68266`（`NRestarts=0`），`credentials.py` / `question_runtime.py` / `question_notices.py` SHA256 与 `main` 一致。`qq-bot-postgres-node`（PID `3417`）、`gaoji-vm`（PID `3692101`）、`gaoji-cluster-worker`（PID `3255`）及 `maxx`（PID `2514837`）均保持未重启，备库 `qq_bot_standby` 维持 `streaming / async`。
- 部署后连续检查 `/health/qq-official` 均返回 HTTP 200 `state="ready" / healthy=true / message_gap=false`（`observed_at` 1794770425、1794770438、1794770447、1794770485、1794770494`），无启动或 QQ 网关报错；既有切换前已每 90 秒出现的 `sandbox maintenance error=SandboxError` 日志仍存在（未改动既有 VM 或 `/work`）。全程未向真实群或私聊发送测试消息；用户已明确取消 F7 实测，真实 QQ 对话与模型端到端交互仍待用户后续按需实测。

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
