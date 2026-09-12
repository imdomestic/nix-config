# maxops —— fleet 控制平面

本页记录 maxops 的定位、与 Max 的边界，以及本 fleet 的配置选择。
2026-09-08 按当前源码和 Nix 求值结果修订；已实现能力与后续建议分开描述。

通用协议、实现和原生 NixOS 模块属于独立仓库
[HCHogan/maxops](https://github.com/HCHogan/maxops)。本仓库只拥有 fleet inventory、
客户端授权、执行/部署 profile、凭据引用和部署策略。通用实现细节以其
[architecture.md](https://github.com/HCHogan/maxops/blob/main/docs/architecture.md)
为准；历次实机验收见 [maxops-deployment.md](maxops-deployment.md)。

本次核对基线：`flake.lock` 的 maxops `ebfd2fd`（0.3.0，协议版本 2）和
Max `8ac010e`（0.18.0）。Nix 求值确认 Hub 位于 h610，纳管九台主机：
**b650、h310、h610、r5s、r5sjp、r6s、rpi4、shanghai、tank**。
本页描述源码与声明式配置；九机切换和运行验收记录见部署文档。

## 0. 边界：通用 fleet 管理服务

maxops 提供三类能力：

1. 聚合主机、systemd、Nix 运行状态及既有监控数据，保留来源和不确定性。
2. 执行可追踪、可恢复的命令、服务变更、Git workspace 和 Nix 部署操作。
3. 保存 fleet 事件，通过通用查询和 webhook 向任意客户端交付。

Max、CLI、MCP 客户端和脚本使用同一套操作与权限。maxops 不依赖 Max 的
数据库、任务系统、QQ 身份、提示词或消息 IR，也不内置模型推理。
告警交付是通用事件能力；向哪个群发、是否经模型转述，由消费方负责。

Prometheus 继续拥有指标和时序存储，Grafana 提供监控视图。
部署已属于 maxops 的能力范围；deploy-rs、人工 rebuild、直接 Git push 和
其他运维工具继续存在，maxops 的记录不代表整个 fleet 的全部变更历史。

管理范围由 host registry 的 `maxops.enable` 显式选择，不由 `roles = server`
自动推导。b650 已纳管，桌面角色不构成排除条件。当前目标端依赖 Linux/systemd；
Darwin agent、reboot、QQ 身份代理和任意 PromQL 均未实现，不列为默认承诺。

## 1. 消费者与身份

| 消费者 | 当前接入 | 授权主体 |
| --- | --- | --- |
| Max | 原生 Haskell HTTP 工具 | 独立 `max` bearer credential |
| Hank / maxopsctl | HTTP API | 独立 `hank` bearer credential |
| Kennethbot | HTTP API | 独立 `kennethbot` 观察 credential |
| 任意 MCP 客户端 | `maxops-mcp` stdio → HTTP | 启动适配器时配置的 credential |
| 普通程序或脚本 | 同一 HTTP API | 各自配置的客户端 credential |

协议类型不决定信任级别。Hub 根据认证主体及服务端配置决定 host、capability、
repository、deployment 范围；请求体不能填写身份，也没有 QQ uid 委托协议。
凭据目录只用于发现，实际执行仍需重新授权。

本 fleet 当前给 Hank 和 Max 相同的完整管理范围，但使用独立凭据；Kennethbot
保持观察权限。群消息与日志等外部内容仍是不可信输入。Max 自己限制聊天入口，
不能把模型填写的身份当成 Hub 的权限证明。

## 2. 架构

```text
Max / maxopsctl / HTTP 程序 / maxops-mcp
                    │
                    ▼
              Hub（h610）
              ├─ 客户端认证、范围检查、操作派发
              ├─ 持久 job、change、事件与恢复协调
              ├─ Prometheus / Alertmanager
              └─ 各主机 Agent
                   ├─ 非特权观察：systemd、日志、主机事实
                   └─ 独立执行凭据 → 本机 Unix socket → Executor
                                                     ├─ 持久接收与执行去重
                                                     ├─ systemd job runner
                                                     └─ workspace / deployment

Alertmanager → Hub → 通用通知接收端 → Max 等客户端
```

Hub 当前单实例，位于 h610。同机 Agent 监听回环地址，远端 Agent 监听各自
registry 中的 Tailscale 地址。Executor 使用本机 Unix socket，不新增公网 RPC。

Hub 和目标 Executor 分别保存协调记录与执行事实。Hub 的一次 HTTP 失败、
客户端断开或 Max 重启，都不能作为远端操作没有发生的证据。

## 3. 执行与恢复边界

受控执行通过结构化 API 和独立 Executor 实现。服务操作使用 systemd D-Bus；
`exec.run` 明确支持 argv 或显式解释器脚本，由服务端 profile 限制运行身份、
工作目录、期限、资源及凭据引用。因此“API 没有 shell”已不符合当前能力。

- 提交持久作业需要稳定幂等键，同一逻辑提交重试复用原键；参数变化不能冒充重试。
- 返回 job handle 表示已受理，最终结果通过作业状态和执行凭证确认。
- 服务变更在执行前观察 unit 状态，支持预期 InvocationID 检查，并记录前后状态。
  已可能发生的操作通过观察恢复，不能因丢失应答就再次执行。
- Workspace 使用隔离目录与不可变 revision，读取、修改和发布遵守相应版本前置条件。
  人的 checkout 不作为临时工作目录。
- 部署冻结源码、构建产物与运行基线。激活前重新观察；旧任务遇到外部变更应成为
  `stale` 或 `superseded`，恢复不能覆盖其他工具后来激活的系统。
- 取消等待不等于取消作业。服务变更和激活一旦开始，取消不能被解释为“副作用没发生”。

maxops 的主机锁只协调自己的作业，不能排除人工或外部工具。
`outcome_unknown` 必须保留为独立结果，不能压成普通失败后盲目重试。

## 4. 单一事实来源：operation registry

操作注册表位于 `maxops-proto/src/lib.rs`，统一提供操作名、请求类型、capability、
kind、只读标记、幂等要求、最低协议版本及输入/输出 JSON Schema。
CLI 从中生成参数入口，MCP 从 Hub 的凭据范围目录生成工具，OpenAPI 复用请求类型。
前端不得再手写一份完整操作/权限表；动态授权与参数约束仍由服务端检查。

当前 HTTP 入口是 `GET /v1/operations` 和 `POST /v1/execute`。
后者使用 `{op, params}`，读取返回 200，持久作业提交返回 202 和 handle。
MCP 已实现为 stdio 适配器，Max 当前使用 HTTP，不经过 MCP。

当前注册表有 45 个操作，以下只列能力分组，不复制完整 Schema：

| 范围 | 已实现操作 |
| --- | --- |
| 观察 | `resources.list`、`fleet.overview`、`units.failed/list/status/logs`、`host.facts/metrics`、`deploy.status`、`alerts.active`、`self.status` |
| 执行 | `exec.run`、`units.start/stop/restart/reload` |
| 作业 | `jobs.list/status/logs/cancel/wait/events/result` |
| 工作区 | `workspace.create/status/read/apply/diff/commit/check/publish` |
| 部署与变更 | `deploy.prepare/build/activate/verify/rollback/run`、`changes.status/history` |
| 事件与诊断 | `events.recent/get/list`、`diagnostics.collect`、`remediations.begin/finish` |

HTTP RPC 仍是传输；目录分层、资源发现、结果投影及作业等待属于公共协议，见 §11。
Max 消费这些能力，不再让模型手动安排 HTTP 发现和作业轮询。

## 5. 授权与进程权限

Hub 检查认证主体及资源范围；Agent 区分观察和执行凭据；Executor 执行本机配置
规定的 profile、unit、repository 和 deployment 约束。三者不是原设计的 polkit 链路。

Agent 保持非特权运行，不获得 polkit/sudo 管理授权；Executor 是独立的特权协调器。
普通诊断作业使用受限身份，root operator/activation profile 需要显式配置。
有界输出、资源限制和持久审计不等于能够隔离恶意管理员命令。

九台纳管机器均启用 `readAllUnits`，可读取所有已加载的 systemd 单元状态和日志，包括 service、timer、target、socket 等。Hub 与 Agent 都执行该策略，`units.list` 提供分页、状态和名称前缀筛选，`units.failed` 明确返回覆盖范围；这不代表列出了所有已安装但未加载的单元。`manageableUnits` 独立保留原有专用服务操作名单。

日常诊断使用 `events.recent`（默认最近一小时、最新优先、20 条，上限 50）及摘要，再用 `events.get` 读取有界详情；`events.list` 保留从旧到新的事件回放语义。

本 fleet 已启用 root operator profile。`manageableUnits` 约束的是专用服务操作，
不能宣称它限制了已获 root 命令权限的客户端只能修改这些 unit。

当前采用预授权管理客户端，不要求每次命令额外走 QQ 二次确认。
幂等键、revision、InvocationID 是执行正确性的前置条件，不是用户授权证明。
聊天入口与交互约束由 Max 等客户端实施，maxops 不新增群播报或确认消息的硬依赖。

## 6. 仓库与技术选择

maxops 当前为七个 Rust crate：

| crate | 职责 |
| --- | --- |
| `maxops-proto` | 线协议、操作注册表、共享类型与传输辅助 |
| `maxops-store` | SQLite 持久化、迁移、幂等和事件记录 |
| `maxops-hub` | 认证、范围、聚合和持久协调 |
| `maxops-agent` | 目标机观察和经认证的执行转发 |
| `maxops-executor` | 本机执行、完成凭证、workspace 和部署 |
| `maxopsctl` | 通用 CLI |
| `maxops-mcp` | stdio MCP 适配器 |

当前使用 Tokio、zbus、reqwest、Serde/Schemars、Utoipa、SQLx/SQLite、color-eyre
和 jiff；工具环境是 devenv，正确性测试用 nextest，基准用 Criterion。
MCP 适配器当前直接实现协议，并未使用原设想中的 rmcp。
发布的是 Nix package/closure，不把“单静态二进制”作为已验证的交付保证。

数据库保留必须跨重启存在的作业身份、幂等、版本、执行结果和事件。
目录缓存、展示裁剪等瞬态逻辑不需要增加持久业务表；Max 也无需复制远端 job 状态机。

## 7. 观测与失联判定

观测必须区分事实、缺失和推断。Agent、exporter 与 Hub 位于不同观测路径：

| 观测 | 能得出的结论 |
| --- | --- |
| Agent 和 exporter 均可达且数据新鲜 | 两条观察路径可用，仍需查看具体服务状态 |
| 只有 Agent 可达 | exporter 或其采集路径不可用，不能断言主机故障 |
| 只有 exporter 可达 | Agent 或其访问路径不可用，不能断言控制进程一定崩溃 |
| 两者均不可达 | 当前无法观察；断电、网络分区、ACL 等原因仍待核实 |
| 缺失、陈旧或有歧义的样本 | 明确返回 unavailable/unknown/stale，不填健康零值 |

同站点多机失联只能作为诊断线索，不能直接证明网络分区。
`fleet.overview` 保留各来源及局部错误；`diagnostics.collect` 提供有界证据和配置探测。

运行 closure、持久 system profile 和 generation 分开报告。没有可信激活凭证就不能
报告“上次成功部署时间”，也不用符号链接 ctime 推断。`host.metrics` 使用固定表达式
和主机范围选择器；任意 PromQL 尚未开放。

## 8. 与 nix-config 的接口

本仓库通过原生模块选项配置 maxops，不复制上游原始配置文件或维护第二套协议：

- `nixos/hosts/<host>/default.nix`：显式 `maxops.enable` 和独立 `manageableUnits`；`readAllUnits` 默认开启，`readableUnits` 可补充尚未加载的精确单元名。
- `lib/mkInventory.nix`：从 host registry 派生 fleet 数据。
- `nixos/modules/maxops/default.nix`：调用上游 Agent/Executor 模块，配置本机
  凭据、执行 profile、repository、检查和部署 profile。
- `nixos/hosts/h610/maxops.nix`：Hub inventory、客户端授权、Max 工具和告警接线。
- `nixos/modules/monitoring/default.nix`：监控目标、Alertmanager 和告警接入。

监控覆盖与 maxops 管理范围是不同开关：监控目标利用 registry 的 Tailscale 等元数据，
运维操作只覆盖 `maxops.enable` 的主机。添加 registry 条目不自动授予管理能力。

目前九台主机各有本机 repository executor 和 system deployment profile。
h610 使用 `nix-config`，其他主机使用 `nix-config-<host>`；部署名为 `<host>-system`。
它们指向相同远端，但 workspace/check/build 留在声明的 Executor 上，按本机架构构建。
公开远端可读不等于已经拥有 Git publish 凭据，发布仍受远端鉴权约束。

System 与 standalone Home Manager 是不同 closure；当前 fleet 配置的是 system profile。
上游支持 home 类型不代表本 fleet 已配置或部署 home profile。

凭据由 SOPS 与 systemd `LoadCredential` 提供，不进入请求体、日志或 Nix store。
服务单元、执行 profile 和 deployment policy 由各端声明，Hub 的发现结果不能替代目标检查。

## 9. Max 与 maxops 的 API 边界

边界原则：换成 CLI、脚本或其他机器人仍然需要的运维能力，应由 maxops 的
公共 API 或客户端提供；对话和模型运行时能力属于 Max。

下表是当前职责分配；公共协议细节见 §11。

| 能力 | maxops | Max |
| --- | --- | --- |
| 操作和资源 | 定义协议、Schema、权限和执行约束 | 映射模型工具，限制聊天入口 |
| 服务与部署 | 完成领域执行、验证和恢复 | 判断目标、参数及需要采取的行动 |
| 作业 | 持久状态、幂等、取消、事件和远端结果 | 保存引用与逻辑提交键，关联本地任务 |
| 观察和等待 | 提供查询、revision 和有界等待协议 | 接入自己的任务挂起、恢复与唤醒 |
| 结果和证据 | 提供结构化事实、有界日志及可追溯引用 | 控制模型上下文，解释与转述 |
| 通知 | 通用事件交付与重放 | 群路由、消息 IR、用户交互 |

Max 从 registry 的 tools view 派生参数明确的模型工具。`maxops` skill 加载观察和作业读取，
`maxops-changes` 按需加载诊断、命令、服务控制、工作区和部署，并依赖 `maxops` 的共享说明。
完整管理凭据下分别为 19 和 26 个工具；恢复旧目录时也重新分组。调用前仍检查
当前权限，不用缓存目录替代授权。工具描述保留上游摘要，共享操作规则只在 skill 中出现一次。

所有作业提交都由宿主持久化逻辑身份和幂等键，创建 Operations task 并用 `jobs.wait`
程序化观察，不按预估耗时分支，也不让模型反复轮询。maxops 独立拥有去重和远端
作业状态；Max 返回可直接查询的 `idempotency_key`，不把内部任务编号作为远端作业句柄。
`jobs.status/wait/logs/result` 恰选原提交键或 UUID `job_id`，按键读取不发送写入幂等请求头。
恢复先找原回执，首次提交限受理后两分钟内。观察使用单调时钟约束远端 deadline 加
30 秒宽限；未取得远端 deadline 的恢复观察最多两分钟。超时以 `outcome_unknown`
停止并等待核实，不自动创建新键重试。停止本地等待与取消远端作业分别表达。

### 固定 skill 工具包（已实现）

Max 的日常上下文只包含基础工具和 skill 的一行索引。调用 `use_skill` 后，
下一次模型请求一次性获得该 skill 的完整说明及整套工具输入 Schema。
包内容由显式配置确定，不按关键词检索结果、相关性评分或当前问题临时增减。
“完整”指当前授权与平台能力范围内的整包；不可用工具及原因应明确报告。

| skill | 随包加载的工具范围 |
| --- | --- |
| `web` | 搜索、浏览器、知乎和 B 站工具 |
| `sandbox` | 沙箱生命周期、执行、Nix 包查询、文件读写及文件进出 |
| `office` | 文档操作说明及固定依赖的完整 `sandbox` 包 |
| `self-knowledge` | 自知说明与 `inspect_source` |
| `maxops` | 当前权限内的主机、服务、指标、告警观察与作业读取 |
| `maxops-changes` | 当前权限内的诊断、命令、服务控制、工作区及部署；依赖 `maxops` |

共享工具和依赖说明只加载一次，重复调用同一 skill 幂等；依赖关系必须显式声明，
不能从 skill 正文中的工具名自动推断。日常回复、上下文、记忆及任务完成/控制等
基础能力保持可用，避免必须先加载 skill 才能完成回合。

加载集合属于当前逻辑请求或持久任务，在其内部保持稳定；新的独立请求从基础集合
开始，避免群里使用过一次运维工具就永久携带。恢复时重建已加载集合和版本信息，
重新应用当前授权。并发请求分别维护集合，不修改群级全局工具表。

授权上限与模型可见集合分开：task profile 只能收窄父任务的权限上限，不应因父模型
尚未加载某个包而意外丢失可继承能力。子任务仍需加载相应 skill 才向模型展示工具。
加载不能提高 effect/authority 上限，不能绕过撤权或改变工具的重试、deadline 语义。

maxops 公共目录仍可分页、筛选和返回单操作详情，供任意客户端发现与缓存；Max 的
工具启用采用固定整包规则。加载包时只带必要的说明和输入 Schema，不再额外复制
整份 response Schema 或完整 RPC catalog。包大小应通过显式设计和检查控制，不能
为满足预算静默截断说明或随机隐藏工具。`use_skill` 返回类型化加载效果；恢复只接受
宿主持久化的可信回执，同批尚未加载的工具调用会被拒绝。设计见 Max 的
`docs/adr/010-skill-tool-bundles.md`。

当前 Max 的工具入口允许群 `611798505`、`650536599` 及相应镜像对话。
告警只发往 `611798505`。现有 fleet 告警走 Hub → Max 去重/outbox，不经过 LLM；
这与 Max 自身根任务进度经前台模型转述是不同路径。

## 10. 监听与通知拓扑

| 服务 | 当前配置 |
| --- | --- |
| maxops Hub | h610，Tailscale `100.64.0.3:9721` |
| h610 Agent | 回环 `127.0.0.1:9720` |
| 其他纳管 Agent | 各自主机的 Tailscale 地址，9720 |
| Executor | 各主机本地 Unix socket |
| Max fleet 告警接收端 | h610 回环 `127.0.0.1:9722` |
| Prometheus / Alertmanager / Grafana | h610 与 tank 两份，默认端口 9009 / 9093 / 3000 |

两份监控并不使单实例 Hub 和 Max 的通知路径高可用。保留独立 webhook 配置；
未配置独立接收端时，不能宣称已具备绕过 h610 的独立推送通道。
事件按至少一次交付理解，消费端按事件 ID 去重；HTTP 202 不能等同于群消息送达。
当前 Alertmanager 转发和通用持久事件订阅并存，不把历史接收路径写成已切换为 job watch。

## 11. 公共客户端协议（已实现）

协议版本仍为 2；本次是增量扩展。正式契约在 maxops 仓库
`docs/api-client-contract.md`，本页只记录 fleet 与 Max 的消费边界。

| 能力 | 当前接口与边界 |
| --- | --- |
| 错误 | 稳定错误码、受控详情及重试条件；避免把底层敏感输出拼进公共错误 |
| 等待 | `jobs.wait` 有界等待 revision，`jobs.events` 提供可恢复 cursor；等待超时不结束远端作业 |
| 结果 | 状态、详情、`jobs.result` 和有界文本日志分离；列表分页，明确截断和局部错误 |
| 发现 | catalog 的 summary/tools/full view 与单操作详情；`resources.list` 按权限发现主机、执行 profile、repository 和 deployment profile |
| 部署 | `deploy.run` 持久推进冻结计划至 built 或 verified；原有阶段原语保留，基线冲突停止，未知结果只观察恢复 |

这些能力服务于所有客户端。Max 把公共等待映射到既有任务运行时，不复制部署状态机。
Max 的工具按 §9 的固定 skill 包整体启用，目录筛选不是动态选择工具的依据。
一次领域操作可以包含多个确定性阶段，内部仍保持查询、提交、等待和结果投影的职责
清楚；不接受任意工作流 DSL，也不内置自然语言自动修复引擎。

## 12. 更新与验收规则

- 本页维护当前源码与配置边界；具体操作和 Schema 以 maxops registry 为准。
- [部署文档](maxops-deployment.md) 保存版本、配置范围与带日期的实机证据；
  后续扩容不能改写旧试点的验收结论。
- Nix 求值、原生构建、单元/DB 测试、VM 测试及实机操作是不同证据。
  只读 health 成功不能证明写入、恢复或部署验收通过。
- 更新协议时同步 maxops 的设计和测试，再更新消费方 pin、适配与部署文档。
  实机状态以部署文档中的完成记录为准，更新 pin 不等于完成激活。

### 2026-09-07 发布约束

本次同时更新 Max 和 maxops pin。先升级所有 Agent/Executor，再升级 h610 Hub，
最后切换 Max；执行 profile 发现需要新的 Executor 协议。maxops 的 SQLite 迁移前
对 Hub 和各 Executor 做一致性备份；Max 的真实数据库验收与生产只读健康检查分别记录。
Max 的旧持久管理授权因 effect 指纹收紧会安全失效，不修改历史授权或重放旧任务。
