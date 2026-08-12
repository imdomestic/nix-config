# maxops —— fleet 控制平面

23 台机器、4 个人、跨物理站点。这份文档定义 `maxops` 是什么、边界在哪、
以及为什么每个决定是这么定的。

配套的仓库是 `github.com/HCHogan/maxops`，作为 flake input 进 nix-config。

---

## 0. 边界：maxops 做什么，不做什么

**做三件事：**

1. **聚合** —— 把 Prometheus 的指标、systemd 的 unit 状态、NixOS 的 generation
   信息合成一个"这台机器现在怎么样"的答案。
2. **受控变更** —— 重启服务这类操作，带身份、带白名单、带审计。
3. **主动触达** —— 告警不等人问，自己发到群里。

**明确不做：**

| 不做 | 归谁 | 为什么 |
| --- | --- | --- |
| 时序存储、PromQL 引擎 | Prometheus | 没有任何理由重造 |
| 部署（`nixos-rebuild switch`） | deploy-rs | 风险等级完全不同，见 §9 |
| ~~单机 Web 面板~~ | ~~cockpit~~ | **cockpit 已于 2026-08-12 从全 fleet 删除**（理由见 `nixos/profiles/server.nix` 里那段注释：NixOS 上它 15 个页面里大部分没有后端）。原本「给 cockpit 加一个 fleet 标签页」的定位随之作废 —— 浏览器里的 fleet 视图归 Grafana |
| QQ 协议、消息收发 | max | max 只是 maxops 的一个 notify sink |

最后一条要强调：**名字叫 maxops，但代码里 max 不特殊。** 它和 matrix、
邮件、webhook 平级，都是 `notify::Sink` 的一个实现。这台 fleet 以后换个
聊天平台，maxops 不用动。

### 管理范围

```nix
managed = kind == "nixos" && lib.elem "server" roles;
```

10 台：`h610 r2s r5s r5sjp r6s rpi4 shanghai tank x470 aarch64-wsl`。

判据用 `roles` 而不是 `kind`，因为**真正的分界是"服务器"还是"漫游设备"**，
不是操作系统。b650、m16、gpd 这些是 NixOS，但它们和 MacBook 一样会合盖
离线，一样没有要运维的服务。

**不支持 darwin，三个理由**（这三条对 NixOS 桌面同样成立）：

1. **控制侧价值接近零。** 三台 darwin 的 `roles` 全是 `["desktop" "gui"]`。
   没有要在群里重启的服务。
2. **安全模型塌一层。** §3 的地基是 polkit —— agent 非特权 + 内核级白名单。
   darwin 上没有 polkit，只能 launchd + sudoers，darwin agent 会是全体系里
   唯一的宽权限节点。而 hub 是统一的，**最弱的 agent 决定了 hub 被攻破时的
   实际爆炸半径**。为三台笔记本拉低整体模型，不划算。
3. **漫游设备污染告警。** 合盖即离线，在 Prometheus 里永远是 down。最后一定
   要把它们排除出告警，那剩下的只是一张 CPU 曲线图 —— 有点意思，不是运维。

一个边界情况：`aarch64-wsl` 虽然声明了 `server`，但它跑在别人的 Windows 上，
宿主休眠它就没了 —— 纳入管理没问题，但**告警规则里要按漫游设备对待**，
否则它会是噪声的主要来源。

**唯一的例外**是 `x86_64-headless` / `aarch64-headless`：`kind = "home"` 但
`roles = ["server"]`。如果它们是真的非 NixOS Linux 服务器，那么有 systemd、
大概率有 polkit，§5 的三层模型能原样搬过去。**这才是扩展的第一优先级，
远在 darwin 之前。**

---

## 1. 为什么值得单独一个项目

不是因为代码量，是因为**它有三个互不信任的消费者，而它们必须共享同一套
操作定义和同一套权限判定**：

| 消费者 | 协议 | 身份来源 | 信任等级 |
| --- | --- | --- | --- |
| max（QQ 群） | MCP over HTTP | QQ uid，由 max 代为断言 | **最低** |
| Claude Code（你的笔记本） | MCP over HTTP | bearer token | 中 |
| `maxopsctl`（终端） | REST | bearer token | 高 |

"最低"那一行是整个设计的约束条件：**群消息是不可信输入，而它最终会变成
对 fleet 的操作请求。** 群里任何人转发一段带指令的文本，都会进 LLM 的
上下文。这不是假想威胁，是这类 bot 的默认状态。

如果不单独做：

- 塞进 nix-config → 变成一堆 `writeShellScript`，权限判定散在各处，没法测试。
- 塞进 max → 绑死在 QQ 上，cockpit 和 CLI 用不了，而且把"聊天机器人"和
  "有 root 能力的控制平面"编译进同一个进程，是错误的信任边界。

---

## 2. 架构

```
                          ┌──────────────────────────────┐
   QQ 群 ──► max ────────►│                              │
                          │                              │──► maxops-agent ×N
   Claude Code ──────────►│         maxops-hub           │    (每台机器，tailnet)
        (MCP/HTTP)        │      (跑在 tank 上)          │
                          │                              │──► Prometheus (PromQL)
                          │  · inventory（nix 生成）     │
                          │  · policy（nix 生成）        │◄── Alertmanager (webhook)
                          │  · operation registry        │
   maxopsctl ────────────►│  · audit log                 │──► notify sinks
        (REST)            │                              │      └─► max ─► QQ 群
                          └──────────────────────────────┘      └─► matrix
```

hub 一个实例，跑 tank。agent 每台机器一个，只监听 tailscale 地址。

---

## 3. 核心决定：per-host agent，不是 SSH

这是地基，先论证它。

**朴素做法**是 hub 拿一把 SSH key，需要干活时 `ssh root@tank systemctl restart nginx`。
用 `authorized_keys` 里的 `command=` 做 forced-command 限制。

**不采用，因为 forced-command 是在给一个通用信道打补丁。** 你会写一个 shell
wrapper 去解析 `$SSH_ORIGINAL_COMMAND`，然后开始和引号、分号、glob 搏斗 ——
而信道另一端是一个读群消息的 LLM。任何一个解析疏漏都是 fleet root。这个方向
的每一步都在做减法，而减法很难做完。

**agent 的做法是做加法**：线上只存在你显式实现的那几个 RPC。没有 shell，
没有字符串拼接，没有"如果参数里有分号会怎样"。攻击面等于 API surface，
而 API surface 是你写出来的、可枚举的、可测试的。

三个通常反对 agent 的理由，在你这里都不成立：

- *"要部署到 23 台机器"* —— 你有 deploy-rs 和统一的 `base.nix`，加一个模块
  是一行。这个成本对别人是真的，对你接近零。
- *"多一个常驻进程"* —— agent 是个几百行的东西：systemd D-Bus 查询、journald
  读取、几个 `/proc` 文件。（原文拿 cockpit 作类比说「你已经全装了」——
  cockpit 现在删了，但结论不变：agent 比它轻一个量级。）
- *"要管一套新的认证"* —— 你已经在用 sops-nix 下发密钥，多一个 per-host token
  是复制现有模式。

**而 agent 换来一个 SSH 给不了的东西：agent 可以不是 root。**

在 NixOS 上，agent 以专用非特权用户运行，配一条**从 Nix 白名单生成的 polkit
规则**，只允许它对特定 unit 调用 `org.freedesktop.systemd1.manage-units`。
读日志靠 `systemd-journal` 组。

结果是：**即使 agent 二进制被完全攻破，它能做的也只有重启白名单里那几个
服务。** 不是"我们尽量限制它"，是内核层面它没有别的能力。

这条路只有在 NixOS 上才顺畅（polkit 规则和白名单从同一份 Nix 配置生成，
不可能漂移），而你整个 fleet 就是 NixOS。这是这套设计贴着你的环境长出来的
部分，换个环境我不会这么建议。

---

## 4. 单一事实来源：operation registry

如果 maxops 只有一个设计原则值得记住，是这条。

**每个操作只定义一次**，MCP tool schema、REST 路由、CLI 子命令、权限
capability 名、审计事件类型，**全部从这一份定义派生**。

```rust
// maxops-proto/src/ops.rs
operation! {
    name: "units.restart",
    summary: "重启指定机器上的一个 systemd unit",
    kind: Mutating,                      // → 决定要不要审计、要不要二次确认
    capability: "units:restart",         // → policy 里用这个名字
    params: {
        host: HostRef,                   // → 类型即校验：必须在 inventory 里
        unit: UnitRef,                   // → 必须在该 host 的白名单里
    },
    returns: UnitStatus,
}
```

没有这层，加一个操作要改五个地方，然后 MCP 的 schema 和 REST 的行为
慢慢对不上 —— 而 LLM 是照着 schema 调用的，schema 一旦说谎，故障模式极难
排查。

派生关系：

```
                    ┌─► MCP tools/list 的 JSON Schema
                    ├─► REST 路由 + OpenAPI
   operation! ──────┼─► maxopsctl 子命令 + --help
                    ├─► policy 里合法的 capability 名（拼错编译不过）
                    └─► 审计日志的事件类型
```

### 操作清单（v1）

**只读**（全群可用）：

| op | 说明 |
| --- | --- |
| `fleet.overview` | 每台机一行：在线/失联、failed unit 数、负载、磁盘水位 |
| `units.failed` | 全 fleet 或单机的 failed unit —— 预计最高频的一个 |
| `host.facts` | uptime、内核、**当前 NixOS generation 及激活时间** |
| `host.metrics` | CPU/内存/磁盘/网络，来自 Prometheus |
| `units.list` | 白名单内的 unit 及状态 |
| `units.status` | 单个 unit 详情：状态、PID、内存、重启次数、上次退出码 |
| `units.logs` | journald，限行数和时间窗 |
| `alerts.active` | Alertmanager 当前告警 |
| `promql` | **只读逃生口** |

关于 `host.facts` 里的 generation：`/run/current-system` 的指向和它的 ctime。
这让 bot 能回答"tank 上次部署是什么时候"、"这两台是不是同一个 closure" ——
Prometheus 永远答不了，但这是真实运维里天天问的问题。

关于 `promql`：直接开放 PromQL 查询看着危险，其实不是 —— 它是纯查询语言，
没有副作用。而它让 bot 能回答你没预先设计过的问题，收益极大。**只读操作里
唯一需要防的是资源耗尽**，用 Prometheus 自己的 query timeout 和 max-samples 挡。

**变更**（白名单身份 + 审计）：

| op | 危险等级 |
| --- | --- |
| `units.restart` / `start` / `stop` | 中 —— 限白名单 unit |
| `host.reboot` | 高 —— 单独一档权限，默认只有 hank |

---

## 5. 权限：三层，互相不信任

```
第一层  hub：身份 → capability
        "linwhite 能不能在 tank 上做 units:restart"
        策略从 nix-config 生成

第二层  agent：unit 白名单
        "nginx 是不是这台机器允许被操作的 unit"
        白名单从该 host 的 Nix 配置生成

第三层  polkit：内核级
        "maxops 这个用户有没有权限 manage 这个 unit"
        规则从同一份白名单生成
```

第一层被绕过（hub 被攻破、LLM 被注入），第二三层还在。第二层被绕过
（agent 有 bug），第三层还在。**第三层没有绕过的办法，除非拿到 root
—— 而 agent 本身没有 root。**

### 身份怎么来

max 认证到 hub 用一个 bearer token，同时在请求里带上 QQ uid。
**hub 信任 max 如实转述 uid** —— 这是必要的信任边界，max 已经通过 token
证明了自己是 max。uid → 身份 → capability 的映射在 hub 侧，max 无法影响。

四个人的映射直接写在 nix-config 里，和 headscale ACL 那个
`group:imdomestic` 用同一份人员定义。

### 变更操作的两个额外闸门

1. **二次确认** —— 变更类操作先返回一个待确认的 intent，需要发起人再确认
   一次。这挡住了绝大部分提示注入：注入能让 LLM *提议* 重启，但确认必须
   来自真实用户的第二条消息。
2. **群内播报** —— 每次变更 bot 主动在群里说一句"应 hank 要求重启了 tank
   的 nginx"。四个人的群，这个审计成本是零，但任何异常操作立刻被四双眼睛看到。

---

## 6. 仓库结构

```
maxops/
├── flake.nix                 # packages.{hub,agent,ctl} + nixosModules.{hub,agent}
├── crates/
│   ├── maxops-proto/         # 操作注册表、线协议类型、错误
│   ├── maxops-agent/         # 每台机器，非特权
│   ├── maxops-hub/           # 单实例：inventory / policy / 前端 / 通知
│   └── maxopsctl/            # CLI，REST 客户端
```

### 语言：Rust

- agent 要上 rpi4 / r2s / r5s / r6s 这些 ARM 小机器，单静态二进制、小 closure
  是实打实的好处。
- `zbus` 操作 systemd D-Bus，`rmcp` 是官方 MCP SDK，两个都省掉手写协议。
- 长期常驻、碰特权边界的进程，内存安全不是加分项是必需项。

**Haskell 也完全可行**（你写 max 就是 Haskell，MCP 本质是 JSON-RPC 2.0，
自己搓不难）。如果你更愿意整个基础设施保持一门语言，这个理由足够压过上面
三条 —— 除了 agent 那部分，ARM 上的 closure 大小差别是真的。可以 hub 用
Haskell、agent 用 Rust，但两门语言的成本通常大于收益，我倾向统一 Rust。

---

## 7. 一个容易漏的设计点：失联判定

"机器挂了"有三种情况，必须区分，否则群里全是无用告警：

| 现象 | Prometheus `up{}` | agent 可达 | 结论 |
| --- | --- | --- | --- |
| 机器真的下线 | 0 | 否 | 主机故障 |
| node_exporter 挂了 | 0 | 是 | 服务故障，机器好着 |
| agent 挂了 | 1 | 否 | 控制面故障，机器好着 |
| 网络分区 | 0 | 否 | 和主机故障难分 —— 看其他 host 的可达性 |

**这个合并判断是 hub 存在的价值之一** —— Prometheus 单独看不出来，agent
单独也看不出来。`fleet.overview` 返回的状态应该是合并后的结论，不是原始信号。

网络分区那一行的区分办法：hub 检查同一站点的其他 host 是否同时失联。
shanghai / r5sjp / 家里这三个站点各自成组，整组同时消失是分区，单台消失是故障。

---

## 8. 与 nix-config 的接口

两份文件由 nix-config 生成，hub 只读：

```
/etc/maxops/inventory.json   ← nixos/hosts/default.nix 的 23 台机器
/etc/maxops/policy.json      ← 人员 → capability 映射
```

**inventory 绝不手维护。** 你的 host registry 已经有 `name` / `system` /
`roles` / `ip` / `kind`，直接 `builtins.toJSON` 出来。加一台机器，监控和
控制自动跟上，这是你这套配置最大的结构优势，要吃满。

nix-config 侧新增：

```
nixos/modules/maxops/
├── agent.nix      # services.maxops-agent，在 base.nix 里默认开
└── hub.nix        # services.maxops-hub，只有 tank 开
lib/mkInventory.nix    # host registry → inventory.json
```

agent 模块里最关键的一个选项：

```nix
services.maxops-agent.manageableUnits = [ "nginx" "xray" ... ];
```

它同时生成 agent 的白名单**和** polkit 规则。一处定义，第二三层防线同源。

---

## 9. 为什么 v1 不做部署

`nixos-rebuild switch` 和 `systemctl restart` 看着像同一类操作，其实差三个
数量级：

- 重启服务：影响一个服务，失败了再重启一次，**可逆**。
- 部署：换掉整个系统 closure，可能改防火墙、改 SSH 配置、改网络 —— **可以
  把机器从网上摘掉，然后你再也连不上去修**。r5sjp 在日本，shanghai 在机房。
- 而且部署需要**求值整个 flake**，那是几分钟的重活，还需要 git 状态，
  和"回答一个查询"完全不是一种东西。

deploy-rs 已经解决了这个问题，还带自动回滚。让 bot 碰它，收益小、风险大。

**v1 的折中**：`deploy.status` 只读操作 —— 告诉你每台机器当前 generation
和激活时间，能看出"哪几台还没跟上"。要真部署，你自己在终端跑 `just`。

---

## 10. 端口

~~现状给所有 server 开了 cockpit 在 9090，和 Prometheus 默认端口撞，所以移
Prometheus。~~

**2026-08-12：cockpit 删了**，9090 空出来了（r6s 上现在归 mihomo 的 metacubexd
面板）。Prometheus 保持 9009 不动 —— 让路的理由虽然没了，但那个端口已经写进
两份监控配置和看板，再挪回去是净损失。

| 服务 | 端口 | 位置 |
| --- | --- | --- |
| node_exporter | 9100 | 所有 host |
| maxops-agent | 9720 | 所有 host，**只绑 tailscale 地址** |
| Prometheus | 9009 | tank |
| Alertmanager | 9093 | tank |
| Grafana | 3000 | tank |
| maxops-hub | 9721 | tank，只绑 tailscale 地址 |

3000 现在只被注释掉的 headplane 占着，实际是空的。
9009 / 9093 / 9720 / 9721 全 fleet 无冲突（已核对）。

绑定地址一律照 `nixos/modules/cliproxy` 的做法：**只绑 tailscale 地址，
不绑 0.0.0.0**。headscale 的 ACL 已经把这四个人圈成 `group:imdomestic`，
公网上压根不存在这个监听，比"开在公网再靠 token 拦"强一个量级。

---

## 11. 分期

排序原则：**价值靠前，风险靠后。**

| 期 | 内容 | 产出 | 风险 |
| --- | --- | --- | --- |
| **P0** | node_exporter 铺 11 台 + Prometheus/Grafana on tank | 全 fleet 可视化 | 无。纯 nix-config，不依赖 maxops |
| **P1** | agent + hub 骨架，只读操作，`maxopsctl` | 终端里能查全 fleet | 无。全只读 |
| **P2** | Alertmanager → hub → max → 群 | **挂了主动说** | 无。只出不进 |
| **P3** | MCP 前端，只读工具 | 群里能问状态 | 低。注入最多骗出信息 |
| **P4** | 变更操作 + 三层权限 + 审计 + 二次确认 | 群里能运维 | 高 —— 前面三期是它的地基 |
| ~~**P5**~~ | ~~cockpit 插件~~ | **作废** —— cockpit 已删，浏览器里的 fleet 视图由 Grafana 承担（入口 `http://100.64.0.13:3000`） | — |

**P2 排在 P3 前面是有意的。** "服务挂了群里自动报警"的实际价值，大于
"能在群里问服务状态" —— 前者不需要有人恰好想起来去问。而且它零风险，
是纯出站。

P0 完全不依赖 maxops，可以现在就动。

---

## 12. 待定

1. **hub 放 tank 还是 h610？** 倾向 tank：h610 已经背了 headscale + max +
   napcat + cliproxy + nginx + docker，而 tank 是存储机、Prometheus 的 TSDB
   要吃盘。反对意见：hub 和 max 在同一台机上通信走回环，少一跳、少一份
   token。但 tailnet 内部这一跳可以忽略。
2. **变更操作谁能用？** 只有 hank，还是四个人都能重启服务、只有 hank 能
   reboot？这个直接决定 policy 的形状。
3. **告警发群里还是发 matrix？** 你已经跑着 matrix-synapse。QQ 群是四个人
   都在的地方，matrix 更适合放详细信息。可以两个 sink 都要：群里发一行摘要，
   matrix 发完整上下文。
4. **`*-headless` 那两台是什么？** 见 §0"管理范围" —— 如果是真的 Linux
   服务器，它们是第一优先的扩展目标，远排在 darwin 前面。
