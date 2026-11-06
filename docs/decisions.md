# 决策记录

这里放**「某样东西为什么不在」**。

这类说明没有可以依附的代码行 —— 一个被删掉的服务、一个故意不开的选项,在配置里
是一片空白,而空白处贴不了注释。硬塞在附近某行上面只会让那行显得莫名其妙。

反过来,「这一行为什么这么写」应该留在那一行旁边,不要搬到这里。

按时间倒序。代码里用 `docs/decisions.md#<锚点>` 引用。

---

## 2026-11-07 · 路由器的数据面用三台 VM 单独测 {#router-tests}

`fleetTests.x86_64-linux.router-<host>`（`tests/router.nix`）在主机的真实配置两侧
各放一台 VM：模拟的运营商（PPPoE 服务端只认测试账号，Kea 发 DHCPv6-PD，radvd）
和一台普通的 LAN 客户端。断言：

- 用 sops 里的账号拨上号，委派的前缀落到 br-lan；
- LAN 拿到 DHCPv4、SLAAC 地址和默认路由，DNS 指向路由器；
- LAN 到 223.5.5.5 和 2400:3200::1（AliDNS，dae 直连）的 SYN 在运营商一侧是内核
  转发出来的（TTL / hlim 63）、做了 NAT、MSS 被压到 1452 / 1432；
- WAN 一侧连得上的端口都是防火墙对 ppp0 开放的；
- WAN 一侧连不到 LAN 里的机器。

smoke 测试只看 unit 有没有起来；拨号、前缀委派、转发和防火墙坏了，unit 照样是绿的
（pppd 改插件名、networkd 改 PD 行为、防火墙换后端都属于这一类）。

- 现在只有 h610：路由器里只有它是 x86_64，能在 tank 上用 KVM 跑。r2s、r5s、r6s、
  gizmo、rpi4 都是 aarch64：r6s 有 KVM，但它自己就是网关、根在 SD 卡上；tank 上
  模拟 aarch64 又太慢。
- 透明代理的分流（国外流量进 dae 的节点）没测：测试里的节点是占位符，后面没有能用
  的上游。
- 在 VM 里 h610 永远到不了 multi-user.target：ACME 下单、ollama 和 qwen 拉模型这些
  开机任务在没有外网的 VM 里不会结束。所以测试等的是 dae.service。将来给 h610 加
  smoke 测试会碰到同一个问题。
- 第一次跑就有发现：h610 的 forward 链是 `policy accept`，运营商那一跳上的任何人都
  能直接连到 LAN 里的机器。IPv6 走委派出去的公网地址，IPv4 只要把 10.0.1.0/24
  路由到 h610 就行。测试用 `lanReachableFromWan` 记下这个现状；转发加上过滤之后
  测试会失败，提醒把这一项删掉。

## 2026-11-06 · 每晚的 input 更新跑在 tank 的定时器上，以 GitHub App 身份推送 {#flake-updater}

`system/modules/flake-updater` 每天 16:00 UTC（国内零点）在 tank 上跑：把
`lib/flake-update-lanes.nix` 里的 input 逐个移到 main 之上，一个 input 一个提交；
求值整个车队，构建 drvPath 变了的 Linux 系统和 home，跑涉及到的 VM 测试；通过的
最长前缀推到 main，失败的 input 二分找出来、单独剔除。预算三小时。

**为什么不用 tank 上的 self-hosted GitHub runner：**

- 仓库是公开的。runner 执行的是触发它的那个分支上的 workflow，跑在 Nix 沙箱之外，
  能用 tank 在局域网和 tailnet 上的身份。GitHub 自己的说法是 self-hosted runner
  "should almost never be used for public repositories"。
- 想把 runner 限定成只跑 main 上的这一个 workflow，要靠组织的 runner group 策略：
  额外的 group 需要 Team 套餐，而且 group 默认只给私有仓库用。
- NixOS 模块关掉了 runner 自更新；GitHub 不再给落后某个发布 30 天以上的 runner
  派任务，而 tank 的系统是手动部署的，夜间任务会悄无声息地停掉。
- runner 要一直连着 GitHub 的 Actions 服务，日志传到 Azure，在国内不可靠。定时器
  只在开头和结尾各用一次 git。

代价是夜间任务本身没有 Actions 界面，靠 App 补上：推上去的最后一个提交带一个
`nightly update` check，内容是这次的报告；出问题就开（或追加到）一个 issue，下一次
干净的运行把它关掉。

**为什么用 App，而不是成员的账号或 machine user：** 推送不该挂在哪个人名下。
`imdomestic-updater`（App ID 5641560）只装在 nix-config 上，权限只有 contents、
checks、issues，没有 workflows，所以它推不了改动 `.github/workflows/` 的提交。私钥在
`secrets/hosts/tank.yaml`，每次运行现换一小时有效的 token。用 App token 推送会触发
ci.yml（`GITHUB_TOKEN` 的推送不会）。

**两个私有 input**（`imdomestic/vex`、`imdomestic/wgconfigs`，都是 `git+ssh`）各用
一把只读 deploy key：GitHub 不允许同一把 key 做两个仓库的 deploy key，所以由
`flake-updater-ssh` 按仓库挑 key。

## 2026-11-06 · VM 测试启动真实主机配置，不写示例配置 {#fleet-tests}

`fleetTests.<system>.<name>`（`flake/outputs/fleet-tests.nix`、`tests/`）把主机
自己的模块列表（`flake/_lib/system-modules.nix`，和 `nixosConfigurations` 是同
一份）放进 NixOS 测试的 VM 里启动，用 `fleet-probe` 拍一份快照。

- 不为测试另写一份「像 h310 的配置」：那样测的是那份副本，真实配置改了它不会跟着变。
  nixpkgs 自己的服务测试 Hydra 已经跑过，我们只测上游测不到的组合。
- VM 里改的只有 `tests/lib.nix` 的 `vmify`：不加载 hardware-configuration 和
  hardwareModules、不开 nvidia、主机名保持真名、不等真实网卡；sops 的每个
  secret 改读一份为测试密钥重新加密的文件，值是占位符。
- `tests/secrets/age.key` 是**只给测试用**的私钥，故意提交在公开仓库里；它只能
  解开测试生成的占位文件，任何真实 secret 都不对它加密。
- 不进 `checks`，理由同 `deployChecks`：`nix flake check` 会全部构建。要 KVM，
  x86_64 在 tank 上跑，aarch64 在 r6s 上跑。
- 判据是快照，不是手写断言：失败的 unit 只能是列了理由的那些；新旧 lock 的快照
  除版本号外应当一致。

## 2026-11-06 · 除 268v 外都用默认内核，不用 linuxPackages_latest {#default-kernel}

26.05 的默认内核是 6.18 LTS。除 268v 外，没有主机再设 `boot.kernelPackages`。

- `linuxPackages_latest` 在 stable 分支上仍然跟主线最新系列：26.05 周期里从 7.1
  到 7.2 再到 7.3，每一步都是新的内核系列加一次重启。默认内核在 stable 更新里只有
  小版本变化，这才是 nixpkgs 自动更新需要的前提。
- 树外模块只为默认内核预构建。nvidia-open、bcachefs、xone、xpad-noone 的 6.18.57
  版本都在 cache.nixos.org 或 cache.nixos-cuda.org 里；7.3 版本都不在。26.05 的
  nvidia 595.71.05 在 7.3 上编不过（`nvidia/os-interface.o`），x470 因此一度无法
  构建（CI 只做 dry-run，没发现），taipan 之前靠 unstable 的驱动绕开。
- tank 和 h310 的根在 bcachefs 上。bcachefs 是树外模块，两种内核用的都是 1.39.6，
  换内核不改变盘上格式。
- r2s、r5s、gizmo 的 DTB 来自内核，6.18.57 里都有；r6s 的设备树由 UEFI 固件提供。
- 268v（Lunar Lake 笔记本）保留 `_latest`：nixos-hardware 要求至少 6.15，6.18 能
  启动，但这一代的显卡和电源管理上游还在改。它没有树外模块，`_latest` 不会编不过。

新机器也用默认内核；硬件确实需要更新的内核时才设 `_latest`，并在这里补一条。

## 2026-11-06 · Pi 主会话优先，不自动派搜索与审查代理 {#pi-subagents-main-first}

Hank 反馈 Pi 仍偶尔出现上方 agent tree，并且委派过于频繁。全局配置已是
`widgetMode = "off"`，本次没有复现它自行变回开启；不能把项目覆盖或残留会话
猜测写成已确认根因。确认的另一处树是 Workflow 工具结果：它独立绘制进度树，
不受 `widgetMode` 控制。

调用过多不能靠 `maxConcurrent = 2` 解决：它限制同时运行的数量，不限制模型
发起任务的次数。插件的 Agent 描述仍鼓励匹配代理类型就委派和主动使用，规则
又要求广泛搜索启动 Agent；Workflow 规则鼓励多阶段/独立验证即使用，与描述中
要求明确 opt-in 的约束冲突。

`home/hank/modules/pi/subagents.ts` 在 bootstrap 装配边界替换 Agent 描述与规则：
先直接调查，只有用户明确要求，或较大的独立子任务确实受益于并行/上下文隔离时
才委派。不默认追加 reviewer 或嵌套代理。Workflow 保留但只接受用户明确要求的
编排意图；不从“复杂”“多阶段”“审查”推导授权。这是提示词策略，不是硬禁用
工具，也不承诺所有模型一定遵守。

同一适配器只屏蔽 subagents 的 `agents` widget 与 `subagents` 重复计数，保留
FleetView、任务执行、schema、通知及其他扩展的 UI。Workflow 结果折叠时只保留
实时标题与规模警告，主动展开仍显示完整树，错误与无任务的 fallback 不截断。
离线渲染测试使用项目 `widgetMode = "all"` 验证设置覆盖也不能重新挂树，并覆盖
异步刷新、展开、警告、错误和两轮生命周期；没有调用付费模型或激活 home。

## 2026-11-04 · Gaoji 固定 tank 主库，不再跨网自动切主 {#qq-fixed-primary}

Owner 明确选择 tank 固定主库、h610 异步灾备、人工确认后切换。两者分别走移动/电信宽带，Tailscale 地址不是同局域网；近三天晚间跨网监控采样丢包约 21–22%，凌晨接近零，同运营商控制组正常。旧 pg_auto_failover 的 20 秒失联判断反复把网络问题变成角色变化；Bot 又因失租约后永久等待而长期停收消息。

应用独立修复安全租约重获（保留 fencing 和暂停边界）；数据库改为 systemd 直接管理 PostgreSQL，禁用 monitor/keeper，固定只读灾备与本地主库，客户端只连接 tank。备库离线不阻塞主库写入，角色检查脚本不允许隐式提升，复制健康检查只告警。原数据目录、TLS/SCRAM、容量约束、备份和人工隔离工具保留。没有“通过提高超时已修好运营商链路”的承诺。

代价明确：tank 真正故障时不再无人值守接管；异步复制可能丢未同步的尾部写入。人工提升必须先证明旧主已隔离、核对 WAL 并接受可能的数据损失，同步修改持久角色和 DSN。流程、迁移/回滚边界与隔离验证见 [固定主库 runbook](runbooks/qq-fixed-primary.md)；上线结果另记 `gaoji-qq-official.md`，此决策不代替部署证据。

**误导过排查的地方：**进程 active 不代表 QQ 可用，数据库恢复不代表旧租约会自动恢复；历史消息缺口不等同当前网关断开。只把候选优先级设成零也不能移除 keeper 的网络分区自停逻辑，所以不采用那种临时改法。

## 2026-11-04 · praxic 的 Linux 构建走常驻 vz VM，不用 Native Linux Builder {#praxic-linux-builder}

Determinate 的 Native Linux Builder(3.24.0)给每个 derivation 起一台新的
1 vCPU VM(host 的 `/nix/store` 经 virtiofs 挂进去),而每次构建的准备阶段在
determinate-nixd 里**串行**:日志里 `fetch Native Linux Builder guest store paths`
约 0.9 s,再加约 0.55 s 起 VM,下一个才开始,`max-jobs = 14` 不起作用。每个
builder 进程还各自连一次 install.determinate.systems。VM 里 `nproc=1` 而
`NIX_BUILD_CORES=14`,大编译也只有一个核。

现在是 nixpkgs-unstable 的 `darwin.linux-builder-vz`(NixOS/nixpkgs#544193,
Virtualization.framework 而不是 QEMU),经 `determinateNix.nixosVmBasedLinuxBuilder`
接入;打开它时 Determinate 模块自己关掉 Native Linux Builder。8 核、16 GiB,
x86_64-linux 走 Rosetta,`vz.nestedVirtualization` 给 guest 一个真的 `/dev/kvm`
(要 M3 以上、macOS 15 以上)。nixos-26.05 没有这个包。

当天在 scratch 目录手动起同一个镜像实测(没经过 launchd):

| | 每个小 derivation | gizmo toplevel(31 个待编) |
|---|---|---|
| Native Linux Builder | 1.75 s | rex 失败(exit 1,日志为空,没追) |
| vz VM,经 build hook | 0.66 s | 31.2 s(输入已在 VM;VM 是空的时 147 s) |
| vz VM,整张图交给 VM 自己的 daemon(`--store ssh-ng://`) | 0.02 s | 27.5 s |

VM 本身 100 个小 derivation 1.7 s 编完,剩下的开销全在 Nix 的 build hook 这一层。
整个 NixOS system 这种大量小 derivation 的活,直接交给 VM 编(build-host 的方式)更快。

NixOS 测试:嵌套 KVM 能用,构建沙箱里 QEMU 只给 `accel=kvm` 也报
`kvm support: enabled`。但最小的单机测试开机到 multi-user 要 104 s;同一个测试
按 aarch64-darwin 跑(`apple-virt`,QEMU 在 macOS 上用 HVF,只有一层)只要
11.8 s。aarch64 的测试优先在 macOS 上跑,嵌套 KVM 留给只能在 Linux 里做的
kvm 构建。Rosetta 跑不了 x86_64 的 KVM,x86_64 的 NixOS 测试仍要真 x86 机器。

打开 VM builder 时,模块往 nix.custom.conf 写明文的 `substituters` /
`trusted-public-keys` / `trusted-users`(值就是 Nix 的默认值)。它们排在 extra-*
那几行之后,Nix 按顺序应用,结果只剩 cache.nixos.org 和 FlakeHub,hank 也不再是
trusted user。`system/modules/nix-settings.nix` 把这三项 mkForce 成空。

切换之后 `nixos-rebuild build --flake .#r6s` 在 `etc-fstab` 上失败:`Native Linux
Builder is disabled via the Determinate configuration.`。determinate-nixd 只在启动时读
`/etc/determinate/config.json` 并重写 `/etc/nix/nix.conf`,switch 不会重启它,于是
nix.conf 里还留着 `external-builders`。daemon 因此认为本机能编 Linux,把
`preferLocalBuild` 的 derivation(unit、etc 文件这类)派给已经关掉的 native builder;
普通 derivation 走 build hook,不受影响。重启后那一行就没了。现在
`system/profiles/darwin.nix` 在 config.json 变了的时候重启它。

**最先误导我的:** 测试 guest 里 `systemd-detect-virt` 输出 `qemu`,看上去像退回了
TCG 软件模拟。aarch64 上 KVM 下它也报 `qemu`,要直接问 QEMU `info kvm`。另外,
切换前的测试都带着 `--option external-builders '[]'`(为了把构建引到手动起的 VM 上),
正好把上面这个问题盖住了。

## 2026-11-04 · Pi 状态栏显示剩余额度，不显示估算会话成本 {#pi-balance-status}

Hank 的 statusline 不再累计展示 `usage.cost.total`：它按客户端价格表估算会话
支出，不是上游账户余额，Rewind 型号沿用公开 GPT 价格时也不是实际账单。
只有带 `rewind/` 前缀的 CLIProxy 模型显示从专用接口取得的有限剩余额度；其他
模型、无限额和失败查询不占位，也不回退成 `$0`。已确认的零余额仍显示。

余额鉴权留在 gizmo 的 Rewind 插件内，与模型请求共享设备会话；Pi 只用已有
网关调用密钥读取缓存后的白名单字段。接口与边界见 `docs/rewind.md#balance-in-pi`。

## 2026-11-04 · Pi 只保留下方 FleetView，移除 Magic Context {#pi-bootstrap}

Hank 的 Pi 由单个 `hank-pi.ts` 入口调用 `home/hank/modules/pi/bootstrap.ts`：
装配渲染适配器、输入框、statusline，再注册 subagents，不再用不同入口文件的
发现顺序表达依赖。CC 与 better-render 的安装/清理边界仍由 `render.ts` 管理。
`widgetMode = "off"` 关闭上方 Agents 树及重复计数，`fleetView = true` 保留下方
列表；沿用无空行、两格缩进与异步 session 启动修复。

删除 Magic Context 的加载入口、配置声明、包、lockfile、专用测试及只供它使用的
JSONC 合并脚本。它虽已禁用，仍有模块加载、启动内存和 profiler 开关轮询开销，
不再为将来可能启用而常驻。原生 `compaction.enabled = true`；不删除用户已有的
`~/.config/cortexkit/` 或 `~/.local/share/cortexkit/magic-context/` 数据。
渲染测试现在直接加载生成入口并启动真实离线子代理，验证只挂载下方列表和两轮清理。

## 2026-11-03 · Pi 状态栏在子代理列表上方，不留纵向空行 {#pi-fleet-footer}

Hank 的底部顺序固定为输入框 → statusline → 操作提示 → main / 子代理列表。
不改 Pi 本体：statusline 仍从自定义 footer 取得分支与扩展状态，但实际渲染为
`belowEditor` widget；同一个扩展入口先注册 statusline，再注册 subagents，保证顺序。
`pkgs/pi-tintin-subagents/compact-fleet.patch` 只删除 FleetView 的提示后与列表末尾
两行空白，保留每行两格缩进和全部导航逻辑。原生 footer 不重复显示状态栏。
`scripts/check-pi-ui.sh` 与 `scripts/check-pi-subagents.sh` 覆盖主题、宽度、布局、
方向键选择、工作流、禁用后重启用和卸载；不需要系统重建。

## 2026-11-03 · home 自动同步只在自己编得动的机器上,没有中央构建机 {#home-sync}

h310、h610、tank、taipan、seraph、encore 和 r6s(小盒子们的构建机)每小时自己从
GitHub 解析 main,在本机构建并激活每个账户的 home(`system/modules/home-sync.nix`)。
其余机器不自动同步:

- r2s、r5s、gizmo、rpi4、tokyo 连求值都不该在本机做
  (`docs/incidents.md#arm-boxes-oom-on-local-build`),home 继续走 deploy-rs。
- Mac、WSL、没有 tsName 的台式机和三台 `kind = "home"` 也不在内:先在 SSH 够得着、
  坏了有告警的机器上跑稳。
- 想过「tank 集中构建全部 home,各机只拉 store path 激活」:客户端不求值,小机器和
  国内机器都能覆盖。没做,因为它要一台常开的 darwin 构建机、tailnet 上的二进制缓存
  和一份发布清单,而眼下要同步的只有这几台本来就编得动的机器。
- 门禁只有「在本机编得过」。llm-agents 机器人用 `GITHUB_TOKEN` 推送,不触发
  ci.yml;等 CI 绿灯,它的提交就永远同步不下来。

实测(h310,4 核 / 7 GB):root 无 GitHub 密钥也能求值 home(私有 input 只有 system
模块用);单个 home 求值 15 s、峰值 600 MB,四个账户 dry-run 共 1.5 min、峰值 1 GB。

## 2026-11-02 · Pi 子代理与工作流用 tintinweb，同一套界面不再叠加编排器 {#pi-tintin-subagents}

Hank 的 Pi 加入固定版本 `@tintinweb/pi-subagents` 0.22.1，提供 Agent、后台
结果与 steering、FleetView 和 SubagentWorkflow；不再叠加另一套动态工作流插件。
Nix 只打包发布源码和运行时依赖，SDK 与 typebox 由 Pi 宿主提供，不另装一份。

保留个人输入框、状态栏及 better-render，CC 对这四个工具让出专用渲染器。
普通前台/后台代理池各 2，关闭定时任务，开启用量上报及费用显示；工作流仍使用
上游独立并发池，不把普通池上限宣传成全局预算。配置、用法、权限和验证见
[Pi 子代理](pi-subagents.md)。同进程子会话退出误卸载主窗口渲染的回归见
[事故记录](incidents.md#pi-subagent-renderer-lifecycle)。

## 2026-11-02 · Pi 只加紧凑 Git 状态，不换整套 TUI {#pi-git-status}

保留 Hank 的中性灰白输入框和单行状态栏，不用 `pi-open-tui` 接管界面。
分支后只在有状态时追加 `[+2 !1 ?3 ↑1]`：`+` 已暂存、`!` 未暂存修改、
`?` 未跟踪、`»` 重命名、`✘` 删除、`=` 冲突、`$` stash、`↑`/`↓` 领先/落后。
计数按文件（stash 和提交数除外），使用当前 Pi 主题颜色；干净时不显示括号。

`home/hank/modules/pi/statusline.ts` 异步读 NUL 分隔的 Git porcelain v2，
仅在启动、开始新任务、分支变化和 `edit`/`write`/`bash`/`powershell` 执行结束时
刷新；`read` 等只读工具不触发。取消每 5 秒的轮询，避免空闲时定时唤醒与 Git
子进程开销；外部编辑或 shell 修改留到下一次任务刷新，不保证即时显示。
不在渲染路径跑 Git，不自动 fetch。查询限时 2 秒，失败时隐藏旧状态，卸载时
取消查询。`bash scripts/check-pi-ui.sh` 覆盖无轮询、事件过滤、真实临时仓库、
刷新生命周期和九套主题的两种色彩模式。

## 2026-11-02 · cliproxy 在出境点 gizmo 上,不在 tank {#cliproxy-on-gizmo}

cliproxy 的上游(OpenAI、Google)本来就从 gizmo 出境:tank 经网关 r5s 的 dae 走
`im` 组的反向隧道,隧道的 bridge 端就是 gizmo,有时还先经 h610 的 portal,多跨
一次移动↔电信。放在 tank 上时,海外的调用方(悉尼的 praxic,kenneth 和 linwhite
的 Mac)要先进国内再出去,跨两次境;放在 gizmo 上,国内的调用方跨一次,海外的
不跨。

调用量(tank 上 cliproxy 3 天的日志):tank 本机(Max、gaoji)4673 次,praxic
609,aegis 178,gizmo 159,alex 119。最大的调用方还在 tank,所以先比了 tank 到
gizmo 的两条路,北京时间 11-01 23:00 前后(一天里最差的时段)从 tank 测:

| | tailscale 直连 gizmo(IPv6) | r5s 的隧道 |
|---|---|---|
| ping 丢包 | 15–21% | — |
| 新连接上一个来回,p50 / p90 / 最大 | 0.15 / 1.15 / 2.17 s | 0.50 / 1.05 / 1.94 s |
| 其中超过 1 秒 | 6/40 | 5/40 |
| 下载 185 KB | 约 1.2 s | 约 2.0 s(含 TLS 握手) |
| 已建好的连接上传 400 KB | 中位数约 0.7 s,最长 2.35 s | 0.2–2.6 s |

两条路过的是同一段移动 → 日本,tailscale 不比隧道差。

搬的时候整个 `/var/lib/cli-proxy-api` 从 tank 拷过来:`auths/` 里的 OAuth 凭据,
和 `rewind/device.json`(Rewind 的设备身份,换一个要管理员重新批准)。拷之前先
停 tank 上的服务:两份同时跑会各自续期同一个 refresh token,一份续上,另一份就
作废。tank 上的旧目录没删,但 gizmo 续期之后里面的 token 就过期了,要搬回去得
从 gizmo 再拷一次。tank:8317 和 h610:8317 各留一个转发到 gizmo。

切换后(北京时间 23:35 前后):

- 从 tank 测,Codex、Gemini、Rewind 都通;Rewind 用的是拷过来的设备身份,不用
  重新批准。Rewind 只收 Responses 格式,拿 chat completions 测它会 500,而且这
  一下会让这份凭据进冷却,之后的 Responses 请求也回 503 `auth_unavailable`,
  重启 cliproxy 才清掉。
- 从悉尼的 praxic 测,直连 gizmo 和经 tank 转发都是一次 1.9–2.7 s。praxic 到
  gizmo 走公网直连,270 ms(热点那条线去日本绕远);tailscale 有直连就不会用
  tokyo 的 peer relay。所以海外这边延迟没变好,省掉的是国内那段晚上的丢包。

误导点:

- 第一轮上传用 `ssh root@gizmo 'cat > /dev/null'` 测,8 次里 3 次卡了 10–54 秒,
  看着像 tailscale 这条路不能用。卡的是每次新建 ssh 会话的握手;复用同一条连接
  (ControlMaster)之后,传输本身 0.35–2.35 秒。
- ping 丢 20% 不等于 TCP 跑不动:下载方向的发送端 gizmo 用 bbr,几乎不受影响。

## 2026-11-01 · Pi 输入区中性，状态栏随主题 {#pi-input-status-colors}

Hank 的 Pi 输入文字、上下边框和 `❯` 固定为中性灰白 `#c5c5c5`，不跟随
对话主题、推理档位或 Bash 模式变色；背景仍由终端提供。只在自定义
`PromptPrefixEditor` 的渲染层着色，不改输入内容、光标、鼠标几何或发送文本。

状态栏保留 Claude 风格的分组，但不再复制它的独立 ANSI 配色：路径、分支、
模型、上下文、费用和分隔符都使用当前 Pi 主题的语义颜色。
模型与费用之间的 `ctx 已用/上限 (百分比)` 来自 `ctx.getContextUsage()` 的
当前上下文估计，不是历史 token 总和；压缩后未知的用量显示 `?`，不伪装成零。
完整会话费用仍独立按记录统计并缓存。

`avg tok/s` 功能保留但默认关闭：`home/hank/modules/pi/default.nix` 的
`showTokenRate = false` 同时关闭计时采集和显示。启用后，用每条 assistant 的
真实 `usage.output` 除以 `turn_start` 到 `message_end` 的耗时，包含首 token
等待，不包含后续工具执行或空闲时间；生成中显示 `…`，结束后定格。
不拿输入、缓存命中或字符估算冒充输出 token；出错/中断或缺失计数时不显示速率。
验证入口是 `scripts/check-pi-ui.sh`。

## 2026-10-31 · Pi 的上下文压缩交给 Magic Context {#pi-magic-context}

2026-11-04 已移除，以下为当时的配置；见 [当前决策](#pi-bootstrap)。

Hank 的 dev 档 Pi 保留 `@cortexkit/pi-magic-context` 0.49.33 的包和配置，
目前暂时关闭（`magic-context-settings.nix` 的 `enabled = false`）。
由 `pkgs/pi-magic-context/` 固定发布包及 npm lockfile，使用原生扩展发现机制，
不另装一份 Pi peer 包；关闭 Magic Context 的自更新，由 Nix 更新版本。

Pi 的 `compaction.enabled` 始终取 Magic Context `enabled` 的反值：停用时恢复
原生自动压缩，启用时交给 Magic Context，避免两套管理器重复压缩或同时关闭。
Historian 使用已有 CLIProxy 的 `cliproxy/gpt-5.5` / `low`，
会产生额外的摘要模型用量，不改变主会话模型或其默认值。Dreamer 暂不开启，
避免首次安装就启动定时模型任务。检索使用本地多语言
`Xenova/paraphrase-multilingual-MiniLM-L12-v2` / `q8`，首次使用需下载权重；
选择多语言模型是为了让中文查询能找到英文记忆。

`home/hank/modules/pi/magic-context-settings.nix` 声明设置，激活时合并到
`~/.config/cortexkit/magic-context.jsonc`，保留注释与未声明字段。状态和记忆写入
`~/.local/share/cortexkit/magic-context/context.db`（尊重 XDG 路径），不进 Nix store。
`/ctx-status` 看状态，`/ctx-wrapup` 请求压缩；只安装 Pi 扩展，不给 OpenCode 加载。
移除 Magic Context 时须同时恢复 Pi 原生自动压缩。

验证：`bash scripts/check-pi-magic-context.sh` 在临时 HOME、agent 和数据库中离线
检查停用时恢复原生压缩且不注册工具、命令或创建数据库，再单独启用测试
JSONC 合并、原生 ONNX / Sharp 加载、工具和命令注册、记忆写入及关键词检索。
不下载模型、不调用 LLM、不激活 home。重新启用只需将上述 `enabled` 改回 `true`，
Home Manager 激活后重启 Pi；不删除现有配置、模型缓存或数据库。

---

## 2026-10-31 · Pi 正文交给 better-render，工具卡保留 CC 风格 {#pi-better-render}

Hank 的 Pi 使用固定版本 `pi-better-render` 0.4.0，负责流式 Markdown、代码块、
表格、Mermaid 和公式图片。`pi-cc-extensions` 1.0.8 继续负责 Claude 风格工具卡、
edit/write diff 和思考预览；个人输入框、状态栏保持原样。
CC 的 `enableMarkdownEnhance` 设为 `false`，避免两套 Mermaid 转换叠加。

移除 Pi 的 `pi-math.ts` 扩展入口，不再让两套公式渲染同时介入。
**`pkgs/pi-math/` 不删**：`pkgs/claude-inline-media/` 仍复用它的 MathJax / Resvg，
由 `home/hank/modules/claude-code/default.nix` 引入；删包会破坏 Claude 的媒体功能。
2026-10-20 的旧配置记录保留在 [原决策](#pi-inline-markdown)。

`pkgs/pi-better-render/` 固定 npm 源码及 lockfile，使用发布包内的 MathJax 4 bundle，
并打包 `beautiful-mermaid` 1.1.3；默认关闭运行时 npm 安装与字体下载。
图片继续走 Kitty 协议；Rex 与 Kitty / Ghostty 使用随文字移动的 Unicode
占位符，Rex 识别补丁及滚动实测见 [事故记录](incidents.md#pi-rex-math-ghosting)。
不支持图片的终端回退到字符公式，不保证 tmux 图片显示。

两套扩展由 `.pi/agent/extensions/pi-render.ts` 统一加载。
`home/hank/modules/pi/render.ts` 明确初始化及栈式卸载顺序，避免 `/reload` 后留下
旧的 assistant 补丁，具体复现见 [事故记录](incidents.md#pi-renderer-lifecycle)。
`/better-render status` 检查状态，`/better-render off` 临时切回原生正文；
`/ccstyle` 仍控制工具样式，不必随正文渲染一起关闭。

验证：`bash scripts/check-pi-render.sh` 在独立临时 agent 目录中用当前 Pi 做离线
组合测试，检查真实 PNG、内置 Mermaid、工具卡、思考显示切换、`on` / `compact`、
窄屏重绘、正文开关、消息原文及两轮卸载/重载，不调用模型、不激活 home。
Home Manager 配置须另行求值；真正启用需 `just hm praxic hank` 后 `/reload`。

---

## 2026-10-25 · home 按文件名组装,没有注册表 {#home-by-file-name}

`flake.modules.homeManager`、`users.<account>.{module,dev,gui}`、主机账户条目的
`modules` / `gui` 都删了。一个 home 由 `flake/builders/homes.nix` 在账户目录里按名字
找:`shell.nix` / `interactive.nix` / `dev.nix` 按档位,`gui-<platform>.nix` 按 gui
role,`<host>.nix` 按主机,`default.nix` 每台都要;不存在就跳过。原来同一件事要在
`user.nix` 的注册表、`users` 条目和 host.nix 三处写对应关系,加一个文件要改三处。

共享的 `home/profiles/` 也一起拆了:每个用到某档的账户有自己的 `shell.nix` /
`interactive.nix`,dev 档的工具链是 hank 和 linwhite 各自的 `modules/dev-tools.nix`。
`users.<account>.dir` 让 a123456 用 fendada 的目录。主机名不能和这些文件名重名,
求值时检查。

唯一的行为变化:linwhite 在 encore 上原来单独用 gui-common,现在和她别的 Linux GUI
机器一样加载 `gui-linux.nix`(多了 vicinae、那批应用和 `NIXOS_OZONE_WL`,少了
swiftlint / jdk)。其余 home 的包、托管文件、环境变量都和改前一致,只有 5 个因为
import 层级变了而换了 drvPath。

---

## 2026-10-25 · 没有 home/modules,也没有共享的 GUI profile {#no-shared-home-modules}

账户之间既不共享配置,也不共享偏好。原来的 `home/modules/<app>` 和
`home/profiles/gui/` 名义上是共享的,实际上要么只有 hank 一个人用,要么别人得在
自己那边把它盖掉(linwhite 用 `mkForce {}` 清掉共享的 yazi 主题,kenneth 要从共享的
GUI profile 里排除 wezterm)。现在每个账户在 `home/users/<account>/modules/` 里留
自己用到的那一份,和 2026-10-06 分叉 nixvim 是同一个做法;GUI profile 变成
`<account>-gui-<platform>`。

共享的只剩 `home/profiles/` 的四个档位:它们决定一台机器给多少工具链(小机器靠
`maxTier` 压档),只负责把程序打开,不带主题、键位和参数。

代价是同一个修复要在每份副本里各做一次 —— nixvim 的 `files` 那次就是三份
(`#nixvim-no-files`)。换来的是改自己那份不会碰到别人。全部按原位置引用副本,
搬迁前后 26 个系统、tank 和 45 个 home 的 drvPath 逐一相同。

---

## 2026-10-24 · 没有 zen-browser 的 flake {#no-zen-browser}

`home/modules/zen-browser`(经 `hank-gnome` 进了 hank 所有 Linux GUI 主机)和
`zen-browser` input 一起删了。那个 input 跟着 nixpkgs-unstable,每个用它的 home
都要多求值一整份 nixpkgs,闭包里也多一套 pipewire / ffmpeg / X11 —— 约占这类
home 求值的一成。268v 上 `hank-flatpak` 装的 Flatpak 版(`app.zen_browser.zen`)
不走 flake,留着。同一天 nixvim 的 `enableMan` 也关了(三份都是),`man nixvim`
的 options.json 在 `#nixvim-no-files` 之后已是 home 求值里最大的一块(约 28%)。
45 个 home 的总 CPU 183 s → 125 s。

---

## 2026-10-24 · nixvim 不用 `files` {#nixvim-no-files}

hank、kenneth、linwhite 三份 nixvim 的 13 个 `after/ftplugin/*.lua`(缩进偏好)
原来写在 `programs.nixvim.files` 里。`files` 的每一项都是一整份 nixvim 子模块
求值(`modules/top-level/files` 把全部插件模块再 import 一遍),13 项加主配置就是
14 份。现在写成 `extraFiles."<path>".text`,一个普通文本文件,生成的文件和每项
设置逐个核对过,完全一致。

实测 `hosts/taipan/hank` 求到 `activationPackage.system`(单线程、无缓存):CPU
5.65 s → 1.54 s,分配 2.1 GB → 0.4 GB,thunk 3245 万 → 441 万。45 个 home 求到
drvPath 的总 CPU 377 s → 259 s。

线索是 assertion 数:这个 home 有 12,286 条,其中 12,160 条是 nixvim 的"选项已删除",
每条正好重复 14 次。一开始以为是 Determinate 的并行求值在 GC 锁上打架
(`nix flake show` 采样几乎全是 `GC_mark_from` / `__psynch_mutexwait`),但
`eval-cores 1` 和 `GC_INITIAL_HEAP_SIZE=20G` 都没让它跑完 —— GC 只是放大器,
根子是每个 home 本身就太重。

---

## 2026-10-24 · home 里没有 devenv {#devenv-not-in-home}

`home/profiles/dev.nix` 原来装 `inputs.devenv` 的 devenv(钉在 v2.3)。它自带
一份打过补丁的 nixpkgs,还用 crate2nix 把每个 Rust crate 展开成一个 derivation:
dev 档 home 求值时间的约 40% 花在它身上(单独求它的 drvPath 3.86 s,nixpkgs-unstable
的 devenv 2.4.0 是 0.86 s,其中大半是 home 本来就要付的 nixpkgs 导入)。devenv 平时
只在项目的 devshell 里用,所以包和 input 一起删了;`devenv.cachix.org` 的 substituter
留着,devshell 里的 devenv 还要用。删掉后 45 个 home 的总 CPU 259 s → 183 s。

---

## 2026-10-24 · 没有 darwin/,主机在顶层 hosts/ {#system-dir}

registry 早就不分平台了,目录还停在 NixOS 时代:Mac 和只有 home 的机器住在
`nixos/hosts/` 下,NixOS 和 nix-darwin 共用的模块(nix、users、home-manager-cli、
sudo-pwfeedback)在 `nixos/modules/`,而 darwin 专属的只有一个 profile 加两个模块,
单独占着一个顶层 `darwin/`。现在主机统一在 `hosts/`,`nixos/` 改名 `system/`,
darwin 的东西并进去(`system/profiles/darwin.nix`,linwhite-smb 两个版本成了
`system/modules/linwhite-smb/{nixos,darwin}.nix`)。顶层于是正好对应两个闭包:
`system/` 和 `home/`。一个模块属于哪个 class,看它在 `flake/modules/<class>.nix`
里的注册或谁 import 它,不再看目录名。

---

## 2026-10-23 · marble 不开防火墙 {#marble-no-firewall}

其余 NixOS 主机这天全部打开了防火墙(之前 marble、tokyo、gizmo、r2s、r5s、
x470、tank、h610、rpi4、r6s 都是关的)。marble 例外:它是跑在 Droidspaces 里的
容器,和 Android 共用网络命名空间,NixOS 的 `networking.firewall` 改写的就是这台
手机自己的 netfilter 规则,会和 Android 的 eBPF / iptables 防火墙打架。那里的
防火墙归 Android 管,这台的 sshd 也因此 `openFirewall = false`。

---

## 2026-10-23 · AeroSpace 不在 nix-darwin 里 {#aerospace-in-home}

原来是 nix-darwin 的 `services.aerospace`,配置是整机一份,所以 hank 和 linwhite
各写一个系统模块(`nixos/modules/aerospace/{hank,linwhite}.nix`)、由 host 选一个。
键位是个人偏好,放在系统闭包里意味着改一个键要 root 加整机重建,而一台 Mac 上
两个人的键位也没法共存。Home Manager 26.05 有 `programs.aerospace`(配置写进
`~/.config/aerospace`,launchd agent 跟着账户),所以搬进各自的
`home/users/<account>/aerospace.nix`,经 users 表的 `gui.darwin.modules` 加载;
aegis 的诱骗器处理成了 linwhite 在 aegis 上的额外 home 模块。

nix-darwin 的 settings 是带默认值的类型,会把几项默认值写进 toml,其中
`on-focused-monitor-changed` 和 AeroSpace 自己的默认不同;这几项现在显式写出,
praxic / m1elite / aegis 生成的 toml 和原来逐字一致。

**切换顺序:先 `darwin-rebuild switch`,再 `home-manager switch`。** 两个 agent
的 label 不同(`org.nixos.aerospace` / `org.nix-community.home.aerospace`),反过来
做会有一段时间两个 AeroSpace 同时在管窗口。HM 的 agent 第一次启用时 macOS 会
弹"允许后台项目"。

---

## 2026-10-23 · flake-parts + 三张表,但不是纯 dendritic {#flake-parts-tables}

**改之前的问题。** registry 是 `flake.nix` 里 `let` 出来的一个普通值,靠函数参数
传给 `lib/mk*.nix`;要看全车队的模块(monitoring、telemetry、h610 的 headscale
policy、gaoji、qq-bot)只能自己 `import ../../hosts` 再读一遍。主机字段在
`host-options.nix`、`lib/my-host.nix`、`lib/mkInventory.nix` 三处各抄一遍,条目本身
没有类型,`tsName` 拼错不会报错。home 的组合是每台 host 手写 profile 列表,于是
漂了:x86_64-headless(role 是 server)引着 gui.linux,`home/modules/gui` 里 taipan
那段包从来没生效过。

**现在。** flake-parts + import-tree,顶层三张带类型的表:`hosts`
(`nixos/hosts/<name>/host.nix`)、`users`(`home/users/*/user.nix`,按账户名)、
`placements`。home 按档位 `minimal < shell < interactive < dev` 组合,host 只写
`maxTier` 和例外。模块读全车队走 `config.my.fleet`。

**故意没做成纯 dendritic 的三处:**

- **下层模块还是普通模块文件。** 纯 dendritic 要求每个文件都是 flake-parts 模块,
  NixOS 模块写成 `flake.modules.nixos.x = …` 的值,靠闭包读顶层 config。这里两百
  多个模块文件、几十个非模块的 `.nix`(palettes、lib 里的表、pkgs),全包一层的
  收益只是"模块之间也能按名字引用",代价是整仓库 churn、git blame 断掉、还得给
  非模块文件改 `_` 前缀让 import-tree 跳过。所以顶层模块只有 `flake/`、`host.nix`、
  `user.nix`;下层要的车队数据由 builder 转发成 `config.my.fleet`,和原来
  `config.my.host` 是同一个模式。
- **`flake.modules` 不用 flake-parts 自带的那个。** 自带的(`flakeModules.modules`)
  给每个模块套 `_class` 包装,多出几层 `imports`。模块系统用 `genericClosure` 按
  导入深度展开,深度一变,同一个 list 选项里各定义的先后就变 —— 实测 praxic 的
  `system-path` 里 home-manager CLI 从 nix-darwin 自带工具后面跑到了前面。这不只是
  drvPath 变:`system-path` / `home-path` 的 buildEnv 开着 `ignoreCollisions`,两个包
  提供同一个文件时谁在前面谁赢。所以 `flake.modules` 自己声明,值是原样的路径,
  代价是丢了 class 检查(NixOS 模块塞进 darwin host 不会在这一层报错)。
- **目录没按功能重排**成 `modules/<feature>/{nixos,darwin,home}.nix`。同时有
  system 和 home 两侧的功能几乎没有(重名的只有 tailscale,而两边还不是一回事),
  按功能聚合换不来什么,现在的 `nixos/` vs `home/` 还能直接看出改的是哪个闭包。

- **没有"每个 system 只求值一份 pkgs"。** 本想统一注入 `nixpkgs.pkgs`,让
  `packages` 输出和各 host 天然同一个 drv、顺带省求值时间。但 host 的
  `nixpkgs.config` 本来就不一样(x470 `cudaSupport`、gpd `rocmSupport`),它们
  必须是不同的实例;所以 `flake/outputs/packages.nix` 继续从具体 host 的 pkgs 里取。

**验证方式。** 每一步纯重构都要求全车队输出不变:所有 nixos / darwin toplevel、
所有 home 的 activationPackage、systemConfigs、packages、每个 deploy 节点、
ciMatrix 的 drvPath / 值逐项相同。`deployChecks` 不纳入 —— 一项就吃 18 GB、二十多
分钟,而它的内容已经被逐个 deploy 节点覆盖。tank 和 nixidy 的 x86_64-linux 求值
有 IFD(helm 渲染、cabal2nix),mac 上要借一台 x86_64-linux 构建再拷回来。

**误导过我的:**

- 起初以为 `gui.linux` 是"wlroots 那套桌面",想给 host 加一个 `desktop` 字段。
  其实 x470、gpd 跑的都是 GNOME(`nixos/profiles/desktop.nix` 默认开),9950x 是
  WSLg —— `gui.linux` 只是一组 Linux GUI 软件。用哪套是账户的偏好(hank 在 GNOME
  机器上用自己的 gnome.nix + ibus),所以没有 `desktop` 字段,只有 host 的 `gui`
  role 加账户的 `gui.<platform>`。
- 第一次对比时全车队"都变了",其实是快照脚本取了报错的最后一行当值,而那行
  (`Use lib.mkForce value …`)不含 "error"。判断求值成败要看退出码。

---

## 2026-10-20 · Pi 正文与公式内联渲染 {#pi-inline-markdown}

通过 Nix 固定 `Fadouse/pi-math` 0.2.0（提交 `7e6aa628`）及运行时依赖，
沿用 Pi 原生扩展目录发现机制。
入口直接导入 store 中的源码路径，让依赖从同一包的 `node_modules` 解析。
通过 MathJax 和 Resvg 将 LaTeX 转成透明图片，Ghostty / Kitty
可直接放在文字行内。

扩展只修改显示；历史与后续模型上下文保留 Markdown / LaTeX 原文。
不支持图片的终端会显示公式源码。按用户要求声明 `terminal.images = "kitty"`，
覆盖 Pi 在 tmux 下默认关闭图片的检测；递归合并设置，保留终端进度等运行时字段。
Hank 的 tmux 已有 `allow-passthrough on`，但 Pi / pi-math 发出的图片序列没有
tmux DCS 封装，tmux 3.6a 实测仍会吞掉图片；强制开启协议不等于支持 tmux 图片。
`/math-render off` 可在 tmux 中恢复显示公式源码。
`/math-render status` 检查渲染状态，
`/math-render off` 临时关闭公式图片，`/math-render on` 恢复。
现有 Claude Code 风格工具卡、个人输入框和状态栏继续使用。

同日按用户要求移除 `pi-response-renderer` 及其 Nix 包。它只隐藏代码围栏、
压缩部分空行和去掉斜体，未达到预期的正文排版效果；不将这类微调作为完整的
Markdown 渲染方案。此前修过的颜色参数问题保留在
[事故记录](incidents.md#pi-inline-color-parameters) 中。

## 2026-10-19 · Pi 使用 Claude Code 风格渲染扩展 {#pi-cc-extensions}

通过 Nix 固定 `minuque/pi-cc-extensions` 1.0.8 及其运行时依赖，使用 Pi
原生扩展目录发现机制加载。Pi 自身提供的三个 peer 包不打包第二份。
CC Dark / CC Light 主题一同安装，当前选中的主题继续由 Pi 保存。

扩展自己的 `enableEditorPrefix`、`enableCustomFooter` 设为 `false`，
让已有个人扩展继续提供 `❯` 和 Claude Code 同款状态栏。仅合并这两个
字段到可写配置，其余渲染偏好可在 `/ccstyle` 面板调整；`/ccstyle off`
可临时切回 Pi 原生工具渲染，`/ccstyle on` 恢复。

## 2026-10-18 · Pi 状态栏对齐 Claude Code {#pi-claude-statusline}

Pi 的个人扩展以单行显示目录、Git 分支、模型、推理强度和会话费用，
顺序、目录缩写、ANSI 配色和分隔符与 Claude Code 状态栏一致。
其他扩展的状态文本继续显示在下一行，费用统计沿用 Pi 的完整会话记录。

Claude 的状态栏输入提供 5h/7d 额度和重置时间，Pi 扩展上下文没有
等价数据，因此这组字段不显示。费用使用 Pi 记录的模型计价；公开 API
单价及代理估算口径见 [Pi 模型费用](pi-model-pricing.md)，自托管 NInfer 保持零单价。

## 2026-10-18 · OpenCode 迁移到 V2，暂时停用 V1 插件 {#opencode-v2-migration}

共享开发 profile 和 OpenCode Home Manager 模块改用锁定输入提供的
`opencode2` 2.0.30，命令为 `opencode2`。模型、凭据文件引用、shell
指令和两套主题继续通过原生 `programs.opencode` 选项管理；V2 支持这些
V1 配置与主题格式，无需同时重写服务端配置。

按用户选择，先迁移主程序，Supermemory 升级到已有 V2 入口的 2.0.17，
通过原生 `plugins` 字段加载；停用尚未移植到 V2 插件 API 的 model-stats、
notificator、DCP、Markdown 表格格式化、skillful 和 tmux-agent-sidebar 桥。
模型进度 WebSocket 元数据、model-stats 的输入和
补丁保留，供后续移植；停用期间没有 prefill/TPS 插件显示和 OpenCode
侧边栏事件桥。shell-strategy 是指令文本，继续有效。

当前锁定的 Home Manager 仅有 `programs.opencode.tui`，没有 V2 CLI
选项，因此只用它生成不含插件的启动主题配置。V2 首次启动自动将全局
`tui.json` 与已有运行时偏好迁移到可写的 `cli.json`；之后终端设置由
V2 自行保存。旧版为可写 `tui.json` 设置的激活钩子和 skillful 空目录
钩子移除。历史数据库和认证数据应在首次 V2 启动前备份，并通过副本
验证升级，避免将 V1 再指向已升级的数据库。

## 2026-10-11 · 禁用 WSL 的全部推理服务 {#wsl-inference-disabled}

按用户要求关闭 WSL 上的 Qwen/NInfer 84K、262K、vLLM 备用档，以及
llama-swap 和 Tailnet 网关。保留模型、镜像和参数；OCI 档均不自动启动，
五个 systemd 服务通过原生 `enable = false` 声明式屏蔽。

当前机器先停止服务，并在 `/etc/systemd/system.control/` 为上述五个 unit
建立指向 `/dev/null` 的持久屏蔽。未进行整机切换，运行的系统 generation
保持不变；WSL 原有的本地代理禁用修改一并提交。服务、容器、进程和
8000/8001/8100/8101 监听均已停止。

将来重新启用时，除修改声明式配置，还需删除该目录中这五个服务的
屏蔽链接并执行 `systemctl daemon-reload`。

## 2026-10-06 · seraph 采用 SSH 计算节点配置 {#seraph-compute-node}

seraph 作为通过 SSH 管理的计算节点运行，停用全部视频输出能力。
主机入口仅导入基础系统配置，通过 `compute.nix` 声明 SSH 与 NVIDIA
计算支持。两张显卡的显示模块在内核中禁用，GNOME/GDM 系统服务移除。
CUDA 与 Bonsai 继续提供计算和推理服务。

实机检查见 [计算节点记录](seraph-gpu.md)。

## 2026-10-05 · Nixvim 回到 9 月 28 日界面改版前 {#nixvim-visual-rollback-20261005}

按用户要求撤回 9 月 28 日起的整轮视觉改版，以 `bf6e6a2^` 中的
`home/modules/nixvim/hank/default.nix` 为基准。恢复 mini.tabline、mini.clue、
Snacks 原有侧栏/终端/诊断入口和 Evergarden 原始配色；移除自写的
hank-tabline / hank-panels、EOF 斜纹、分层背景、失焦变暗和新 Git 标记样式。

保留随后加入的 Hank Java/JDTLS 配置、LSP 功能和 VS Code 配置拆分。
旧界面文档保留作历史记录。

## 2026-10-05 · seraph 使用 NInfer 承载 Bonsai 2 {#seraph-bonsai-ninfer}

用户指定 Bonsai 2 使用 CraneBW 的 NInfer 三元权重实现，两个模型均采用
NVFP4 KV、174080 token 上下文、174080 token KV 容量、MTP 和单个并发请求。
服务使用 Podman 与 NVIDIA CDI，通过 llama-swap 按需启动并互斥切换。

本次实现从 `origin/main` 的 `973aa36` 创建 `feat/seraph-bonsai-ninfer`，配置中移除旧的
llama-server、PrismML 构建和 bonsai-models 服务。旧方案实测通过的上下文为
主力 81920、Hikari 102400，用户要求的新运行参数由 NInfer 验证。

模型文件与引擎镜像保存在 `/var/lib/` 下。Hikari GGUF 用作转换输入，
主力使用指定仓库中包含 851 个张量的 GGUF。根据用户后续清理指令，旧的
`feat/seraph-bonsai` 分支、旧部署目录、旧 GGUF 与旧引擎已经删除。
显卡模块和当前 NInfer 的转换材料、模型及镜像保留。
174080 参数出现显存不足时，记录引擎缺口与
显存占用，等待用户决定。

## 2026-10-02 · 高级入口使用独立 Tailscale 节点 {#gaoji-isolated-ingress}

不再把 `gaoji.inner.imdomestic.com` 当成 h610 的 DNS 别名，也不直接改成
tank 主机地址。入口配置位于 `nixos/hosts/tank/gaoji-web.nix`，使用原生
NixOS 容器 `gaoji-web` 的 private network namespace，独立运行 tailscaled、
nginx 和 ACME。容器注册为 `gaoji`，由 Headscale 分配自己的 IPv4/IPv6；
宿主机的 Tailscale 身份、路由和 DNS 不共用。它不是额外的 KVM 虚拟机。

机器人、QQ 和数据库仍在 tank 原位置。nginx 通过只读挂载的 Unix socket
连接宿主机的 `gaoji-web-upstream`，由 systemd socket proxy 转发给现有
机器人监听端口，避免经 Tailscale 绕回宿主机。只信任明确的代理来源。
容器的 80/443 仅在自身 tailscale0 上放行；10.233.0.1/10.233.0.2 是
点对点出口，不能作为控制台访问地址。证书凭据由 sops 渲染，只挂载这一份。

首次注册使用短期、单次 preauthkey，不能把 key 或宿主机 tailscaled.state
放进仓库。容器不是 ephemeral，独立状态与证书留在
`/var/lib/nixos-containers/gaoji-web`，重启入口不应产生新的节点身份。
不启用 Tailscale SSH、出口节点或子网广播。

部署必须先验证新节点的有效 HTTPS、认证接口和实时更新，再更新 h610 的
DNS 记录。`gaoji` 由节点自己的 MagicDNS 提供；旧 `kennethbot` 别名跟随
gaoji peer 的地址。找不到该 peer 时保留原记录并失败，不能退回 h610 地址。
只改 DNS 不代表 HTTPS 入口已经迁移；只通过构建也不代表已经部署。

首次上线不整机切换 h610：只给 `headscale-local-dns.service` 安装临时的
`system.control/headscale-local-dns.service.d/50-gaoji-migration.conf`，引用已
构建的原生记录生成器，并为该闭包建立
`gaoji-dns-updater` GC root。这个覆盖在重启后仍有效；下一次包含本模块的
h610 正常切换会自动删除覆盖和 GC root，恢复纯声明式管理。

2026-10-02 已在 tank 上线：Headscale 节点 `gaoji`（ID 48）属于
`kenneth@imdomestic.com`，地址为 `100.64.0.42` / `fd7a:115c:a1e0::2a`。
客户端正常域名访问控制台返回 HTTPS 200，证书校验成功；未登录管理 API
返回 401；旧地址返回 308 并跳转到高级。完整重启容器后节点 ID、IP 和
证书保持不变。h610 仍为 `100.64.0.3`，tank 主机仍为 `100.64.0.4`。
h610 的 Headscale、tailscaled、nginx 以及 tank 的 QQ、数据库和 Max
InvocationID 均未变化。18 台 NixOS 主机配置评估通过，tank 构建并切换成功。

## 2026-09-30 · 浮层保留圆角边框 {#floats-keep-borders}

补全菜单、文档窗、签名提示、which-key、noice 命令行、Snacks 浮动 picker、诊断浮窗
都沿用主题默认的样子：mantle 底加圆角边框。

同一天试过去掉边框、只靠底色分层：浮层比正文亮一级（surface0），文档和预览暗一级，
上下用 `▄` / `▀` 半格收边，picker 和命令行的输入区是一整块更亮的三行。实际用起来
不如带边框舒服，命令行和背后的代码尤其分不清，于是退回，只留下选中竖条和补全列表
避开命令行边框这两处。

误导人的地方：这套无边框方案先在设计稿（固定的 140×40 字符格截图）里看着很好。
截图里浮层背后大多是空白或稀疏的代码；真实使用时浮层压在密集的代码上，一级底色差
不够把边界勾出来，半格边还会把背后那一行文字从中间切掉。

侧栏和底部面板的退后底色、分隔线留空、状态栏去色块、只在正文窗口之间变暗这些
没有受影响，照旧保留，见 `docs/nvim-look.md`。

## 2026-09-28 · 侧栏面板不交给 edgy.nvim {#no-edgy}

Neovim 侧栏（explorer、git、大纲、数据库、lean infoview）由自写的 `hank-panels`
登记和切换，没有引入 edgy.nvim。Snacks 也没有现成的轮子：`Snacks.win` /
`Snacks.layout` 只管 Snacks 自己创建的窗口，aerial、dbui、infoview 都是自己
`:vsplit` 出来的。

edgy 解决的是「别人开的窗口放到哪、多宽」，而这里缺的是「同侧一次只开一个」和
「顶栏上的图标」，这两件 edgy 都不做。位置和宽度在各插件自己的选项里设成一致
（左侧 30 列）就够了。另外 edgy 会在侧栏窗口的 `winbar` 上写标题，和顶栏横线
占用顶层窗口 `winbar` 的做法冲突。

如果以后几个插件抢同一条边的位置或顺序，再考虑用 edgy 只做摆放。见
[侧栏面板](nvim-panels.md)。

## 2026-09-28 · VS Code 声明默认值，GUI 保留用户覆盖 {#vscode-user-overrides}

Hank 的 VS Code 设置不由 Home Manager 的 `userSettings` / `keybindings`
生成文件：这些文件如果链接到 Nix store，GUI 就无法正常保存个人修改。
使用原生 VS Code 扩展贡献点声明默认值，再通过 Home Manager 的 `extensions`
选项安装本地扩展。用户设置和快捷键优先，重新 activation 不会覆盖它们。

没有采用“每次 activation 复制成可写文件”的做法，因为可写不代表 GUI 修改能在
下一次 activation 后保留。也没有维护一套读写 JSONC 的合并脚本；优先级交给
VS Code 本身处理。具体路径、使用方式与快捷键见 [VS Code / Neovim](vscode-neovim.md)。

## 2026-09-27 · 高级 QQ 接入迁到 tank，h610 不再登录同一账号 {#gaoji-qq-tank}

高级的 Bot、QQ/NapCat、主数据库、媒体和 KVM 沙盒集中在 tank。h610 关闭
高级 QQ 服务、健康检查及自动登录定时器，并删除旧的健康指标文件，避免下次
rebuild 恢复第二个登录实例。切换顺序是停旧实例、完整复制并校验账号数据、
先 switch h610 禁用旧服务，再 switch tank 启用新服务；不升级 QQ/NapCat。

tank 的 QQ 数据在 `/var/lib/napcat-gaoji`，WebUI 只监听 `127.0.0.1:6100`。
本机登录隧道改为 `ssh -N -L 16100:127.0.0.1:6100 kenneth@tank`。
登录恢复的密码和尝试记录通过私有文件迁移，不把密钥放进 Nix store；同学
机器人用于提醒的管理凭证不跨主机复制，因此这项跨账号提醒关闭，QQ 健康
状态继续通过 Prometheus 观测。

h610 仍保留数据库热备和 HA monitor，以及共享的域名入口、模型接口和集群
控制服务。这不是第二个高级实例。旧 QQ 数据留作 root-only 回退副本；需要
回退时必须先停 tank，再恢复 h610 服务用户的目录所有权并启动，不能并行登录。
迁移不等于腾讯重新接受旧登录态，扫码和实际群文件投递仍单独验收。

## 2026-09-22 · rpi4 整个 X 域名集走日本，其余默认直连 {#rpi4-x-via-jp}

rpi4 重新启用 dae，但不恢复原来的中国网关策略：默认出口仍是 `direct`，只有
`geosite:twitter` 走日本 `im` 组。这个集合包含 X 的页面、API、图片、视频和
直播域名；除此以外，悉尼网络仍全部直连。

最初试过只代理 `x.com` / `twitter.com` 控制面、让 `twimg` / `twvid` 继续从
澳洲直连；首屏短暂正常，继续滚动后年龄确认立即回来。既然控制 API 已确认全走
日本，剩下的网络变量就是同一 X 会话的媒体/CDN 澳洲出口，因此不再拆分。证据和
误导点见 `docs/incidents.md#rpi4-x-split-age-loop`。原先摘掉全局 dae 的性能依据
仍见 `#rpi4-drop-dae`；这次只扩大 X，不改变其他服务。

## 2026-09-21 · dev profile 里不装 clang / clang-tools,C/C++ toolchain 交给 devshell {#no-clang-in-dev-profile}

nixvim 声明了 `clangd`(`hank.nix` 的 `externalServers`),但这个仓库一个 C/C++
toolchain 都不装。macOS 上用 CLT 自带的 `/usr/bin/clangd` 凑合;Linux 上压根没有
clangd,VimEnter 那个 `executable()` 守卫会直接跳过,要用就由项目 devshell 提供。

**不是图省事没加 —— 加了会在 macOS 上主动弄坏现在能用的环境。** home profile 的
PATH 排在 `/usr/bin` 前面,装上 `clang-tools` 就会盖掉 Apple 那份正常工作的
clangd,不是"多一个选择"而是"换掉一个能用的"。

实测(aarch64-darwin,Apple clangd 21.0.0 vs nixpkgs clang-tools 21.1.8)。发真的
LSP `didOpen` 读 `publishDiagnostics`,文件是完全正确的 vector/string/cstdio:

```
Apple /usr/bin/clangd            0 条
nixpkgs clang-tools 的 clangd    5 条假报错
    No member named 'string' in namespace 'std'
    reference to unresolved using declaration
```

根因是两套 libc++ 头文件串了。nixpkgs 给 clangd 套了 shell wrapper,把 nixpkgs
libcxx 注进 `CPLUS_INCLUDE_PATH`,而 clangd 内嵌的 driver 仍走 Apple SDK 的
sysroot:

```
wrapper 注入   -cxx-isystem /nix/store/…-libcxx-21.1.6+apple-sdk-26.4/include/c++/v1
driver 实际用  /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/c++/v1
```

三个对照,定位到 wrapper 那段 CPATH 注入:

```
clangd-unwrapped(绕过 wrapper)     0   ← 确认就是注入干的
加 compile_commands.json            5   ← 没用,别指望这个能修
加 --query-driver                   0   ← wrapper 见到它就不注入(源码里写死的)
```

`clang` 本身没这个问题(nixpkgs clang++ 编译 + 运行都正常),但单独装它意义不大。
将来真要装 `clang-tools`,`clangd.config.cmd` 必须同时加
`--query-driver=/nix/store/*/bin/*clang*,/usr/bin/clang*`,否则就是上面那 5 条。

Linux 侧**没有实测**。预期不一样 —— 那边没有 Apple SDK,nixpkgs libc++ 是唯一
一套,冲突的前提不存在。这是推断,上 Linux 前值得单独验。

**踩过的弯路:** 一开始用 `clangd --check=file.cpp` 测,加不加 `--clang-tidy` 都是
0 诊断,差点据此断定 Apple 把 clang-tidy 裁掉了。那个模式根本不跑 tidy。真身
55M,`strings` 里 `bugprone-` 97 个、`readability-` 67 个,模块是全的。要测 LSP
行为就得发真的 LSP 请求,`--check` 不算数。

顺带记 clang-tidy 的现状:clangd 21 **默认就开** clang-tidy(`--clang-tidy` 这个
flag 现在是空转的),但默认 check 集是空的 —— 没有 `.clang-tidy` 文件就一条都不
报。要用就在项目里放一个,nvim 这边不用动。

## 2026-09-19 · nixvim 里没有 tailwind-tools,也不全局开类名排序 {#nixvim-no-tailwind-tools}

**tailwind-tools 删掉了。** 上游仓库已归档,nixvim 会报
`plugins.tailwind-tools: This plugin has been deprecated`,而且启用它还会连带
触发 lspconfig 的弃用警告。它原来只负责两件事:类名的色块和 `:TailwindSort`。

色块换成了 Neovim 0.12 内置的 `vim.lsp.document_color` —— 同样问 LSP 的
`documentColor`,认项目真实调色板,少一个插件、也少一个 `server.override`
的坑(那个插件默认会自己再起一份 tailwindcss LSP)。内置渲染把 extmark 写死
在 range 起始列,所以要让色块落在 token 之后,`style` 传的是函数而不是字符串,
渲染由 `hank.nix` 的 `extraConfigLuaPre` 接管。代价是自定义函数下内置不再提供
`hl_group`,高亮组和 extmark 清理都得自己管。

**类名排序(`useSortedClasses`)不在这个仓库里,它是项目配置。** 这条规则在
biome 2.4 里属于 `lint/nursery`,默认关闭,要在**每个项目自己的** `biome.json`
里开,还要用 `options.functions` 告诉它 `cn`/`clsx`/`cva` 这些包装函数。

它的 fix 标记为 **unsafe**,`biome check --write` 默认不会应用。但**不要为此去用
`--unsafe`** —— 那是一刀切的开关,会把所有已启用规则的 unsafe fix 一起放进来。
默认规则(连 biome.json 都没有)下实测:

```
--write          import 排序、格式化,语义不动
--write --unsafe 整行 import 删掉;unused -> _unused;
                 `props.a == "1"` 改成 `=== "1"`;<>…</> 片段拆掉
```

`props.a` 类型是 `number` 时,`== "1"` 在 `a === 1` 时为真,改成 `===` 之后永远
为假 —— 语义被悄悄改了。

正确做法是按规则放行:biome 2 支持在单条规则上写 `"fix": "safe"`,这样普通的
`biome check --write` 就会应用它,别的 unsafe fix 一律不动。实测同一份
`biome.json` 下类名排序生效、而上面那几处危险改写都没发生。所以 `hank.nix` 用的是
conform 内置的 `biome-check`(`check --write`),没有自定义的 unsafe 变体。

项目侧的 `biome.json` 长这样(已实测):

```json
{
  "linter": {
    "rules": {
      "nursery": {
        "useSortedClasses": {
          "level": "info",
          "fix": "safe",
          "options": { "functions": ["clsx", "cn", "cva"] }
        }
      }
    }
  }
}
```

## 2026-09-19 · 暂停 Max 的 iMessage 和微信接入 {#max-pause-imessage-wechat}

按用户要求从 h610 的 Max 配置移除 iMessage 和 WeChat hook，并停止部署这两个
桥接凭据。QQ 和 Matrix 继续启用；加密凭据、消息历史和平台记录保留。
生产库中这两个平台的账户及端点同时设为 `enabled = false`，避免已有镜像关系
继续生成投递。恢复时需要恢复接入配置，并显式重新启用对应账户和端点；旧的
失败或结果不确定投递不会自动重放。

## 2026-09-17 · Gaoji 独立 SSH 运维入口 {#gaoji-native-ssh}

Gaoji 在 h610、h310、tank 使用独立的 `gaoji-operator` 账户与密钥。
2224 端口仅在 `tailscale0` 放行，走原生 OpenSSH 公钥认证，避免 22 端口的
Tailscale SSH 认证接管；原有 SSH 登录不变。该账户强制执行固定 JSON 入口，
sudo 只允许该入口，关闭终端和转发，不向聊天沙盒提供私钥。

私钥仅保存在 h610 的 `/var/lib/gaoji-operations-identity/id_ed25519`，目录
0700、文件 0600，由 systemd credential 提供给控制服务。主机公钥通过已有可信
管理员连接核验后固定在 `lib/gaoji-ssh-known-hosts`。换密钥或目标时旧授权失效。
保留任务授权、持久回执、重启恢复、服务/开机身份复查及最终投递；旧 Hub 任务
不自动转换或重放。旧 MaxOps 专用部署工作流不重新启用。

## 2026-09-15 · Max 运维改用独立 Tailscale 与 SSH {#max-ssh-operations}

运维入口改为开启群内的普通 `ssh hostname`。Nix 与原生 systemd 管理专用
`maxops` netns、tailscaled 和 `max-stack.target` 生命周期；fleet 的 `max`
账户有完整免密 sudo，机器人进程改名 `max-service` 并保留原 UID/GID。

旧 maxops Hub／Agent／Executor、客户端凭据、专用检查与 flake 输入移除。
Gaoji 的控制与计算 worker 保留，旧 ops／部署入口停用，主机清单改用
`clusterControl`；Alertmanager 保留规则与独立 webhook，移除经 Hub 的群告警。
历史决策与事故记录保留。配置、密钥与首次迁移顺序见
[Max SSH 运维接入](max-ssh-operations.md)。当日已完成 10 台 NixOS fleet 切换与
SSH/sudo 验收；h310 的原有 Gaoji 安装失败使 switch 非零，实际新系统已生效，
详见该页的发布记录。Darwin 仅有配置，不在本次实机验收范围。

## 2026-09-13 · 纳管主机用 MagicDNS 名称寻址 {#tailscale-names}

移除 registry 的 `tsIp`，由 `tsName` 同时供部署、监控和服务互连使用。
本机监听在启动时解析并验证 Tailscale 接口地址，数字地址由运行时产生。
不能把所有 `listenAddress` 机械替换成域名：maxops、Headplane 和
Alertmanager 的部分字段只接受 IP，h610 的 nginx 又承载控制平面的启动入口。
这些适配及数据库/NFS 的迁移边界见 [操作说明](tailscale-names.md)。

## 2026-09-12 · hackintosh 的 raycast 为什么不从 unstable 取 {#x86-64-darwin-unstable-drop}

`nixpkgs-unstable` 已经滚过 26.11，那个分支**彻底移除了 x86_64-darwin**：不是
少了几个包，是一碰 stdenv 就 `throw`。hackintosh 是仓库里唯一的 x86_64-darwin
机器，它的 home 里只有一处用到 unstable —— `home/profiles/gui/darwin.nix` 的
`pkgs-unstable.raycast`。于是那一台的 home 求值直接失败。

26.05 里的 raycast 是 1.104.17，`meta.platforms` 仍带 x86_64-darwin，够用。
所以那一行改成按系统挑 pkgs 集，只有 x86_64-darwin 退回 stable，其余 Mac
照旧吃 unstable。

没有选择的另外两条路：把 `nixpkgs-unstable` 整个钉回支持 x86_64-darwin 的旧
提交，代价是全仓库所有机器都失去 unstable 的意义；或者干脆把 hackintosh 从
仓库里摘掉 —— 那台还在用，现在摘不合适。

真正的期限在 26.05 结束支持时：那之后 x86_64-darwin 在这个仓库里没有任何
nixpkgs 可用，hackintosh 要么换机器，要么留在最后一个能求值的提交上。

## 2026-09-09 · gaoji 账户登录与逐次手机授权 {#gaoji-account-mobile-approval}

h610 的 gaoji 控制台使用账户密码登录；管理员可查看管理信息，成员仅可查看机器人状态。
管理操作冻结目标及参数后，向该管理员绑定的 QQ 私聊发送 6 位一次性口令。
口令绑定本人、机器人、操作及网页会话，确认后立即消耗；自动守护也只提出修复，
每次执行仍需本人私聊确认。网页不再使用共享管理员 Token 或电脑上的批准按钮。

账户及批准记录保存在现有 PostgreSQL，授权密钥与 OneBot 凭据由 SOPS 管理，
通过运行时环境文件或 systemd credential 传递。NapCat 启动前只更新现有反向
WebSocket 连接的访问凭据，不替换账号配置及登录数据。首次管理员通过单独初始化
命令创建，随机初始密码写入服务器的私有文件，不进入 Git、Nix store 或服务日志。

控制台使用 `https://gaoji.inner.imdomestic.com`，仅在 h610 的 Tailnet 地址监听，
通过 Cloudflare DNS 验证签发证书；旧域名重定向到该地址。HTTPS 用于保护密码及
Secure Cookie。保留 Fleet、Worker 与 OneBot 的机器凭据，它们不用于人的网页登录。

## 2026-09-07 · gaoji 改名保留数据 {#gaoji-rename}

机器人项目改为 gaoji，input 指向 `zty20040403/gaojibot`。主程序、控制面、Worker、
Prometheus 指标和新控制台域名随之改名；旧域名保留为别名。

保留已有 PostgreSQL schema、状态和缓存目录、NapCat 容器及数据、沙盒 Nix 缓存卷、
归档挂载和加密凭据路径。它们不是展示品牌，自动搬迁会让任务或 QQ 登录状态丢失，
另建缓存卷也会重复占用磁盘。控制面与 Worker 通过显式 stateDirectory 读取既有数据。

外部运维客户端身份和 API 继续保留，只同步获准读取的服务名称。不修改其他机器或
其他人的机器人，不因仓库改名执行系统切换。应用配置中的自定义人格和 QQ 名片需另行同步。

## 2026-09-07 · maxops 执行面扩到八台纳管主机 {#maxops-fleet-full-control}

> 历史方案，已于 2026-09-15 退役；当前流程见 [SSH 运维](max-ssh-operations.md)。

h610 继续作为唯一 Hub；八台纳管主机各自运行 Agent 与 Executor。Hank 和 Max
使用独立 token，但都获得全部 host、job、unit、diagnostic、workspace 与 deployment
权限。Kennethbot 保持只读。每台主机的 manageable unit 仍来自
`config.my.host.maxops.readableUnits`，完整客户端权限不会绕过目标机清单。

每台主机使用独立 execution token。远端主机的同一份 SOPS 文件同时加密给该主机、
h610 和管理员：目标 Agent 读取本机副本，Hub 读取 h610 副本。token 只通过运行时
文件和 systemd credential 传递。

一个 repository executor 同时也是该 deployment 的 builder，workspace 不跨
executor 隐式复制。因此各主机使用独立逻辑 repository ID 与本机 system deployment
profile，虽然它们都指向同一个公开 Git 远端。这样 x86_64 与 aarch64 在本机原生构建，
远端 ref 的 CAS 仍协调多个发布者；人工 push、直接 rebuild 和其他部署工具继续作为
同等事实来源。

---

## 2026-09-07 · maxops 完整执行面先落在 h610 {#maxops-h610-full-control}

> 历史方案，已于 2026-09-15 退役；当前流程见 [SSH 运维](max-ssh-operations.md)。

Hank 和 Max 使用独立 token，但在 Hub 上拥有相同的完整 capability、`nix-config`
workspace 和 `h610-system` deployment 权限。h610 同时运行 agent 与 executor；executor
提供有界诊断 profile 和显式 root operator/activation profile，能运行命令、操作已列入
inventory 的服务、修改冻结的 Git workspace，并按 closure 与业务检查完成部署验收。

其他 fleet 主机仍只部署观察 agent。Hub 会继续显示它们的真实远端状态，但不会因为
h610 已启用 executor 就把其他主机宣称为可执行；需要逐机新增独立 execution token、
executor 和 manageable unit 清单后才能开放写入。这也保留了人工 push、直接 rebuild
和其他部署工具作为同等事实来源，maxops 每次变更前仍须重新观察 Git head、运行 closure
与 system profile。

`nix-config` 使用公开 HTTPS 地址进行 fetch，因此 workspace、check、commit 和未发布
workspace 的构建部署不依赖人的 checkout。远端 publish 仍由 Git 远端自身鉴权决定；
不会把个人 SSH key 或 token 写进 Nix store 来伪造“已有发布能力”。

---

## 2026-09-05 · 删掉 hank tmux extraConfig 里的死设置 {#tmux-dead-settings}

`home/users/hank/default.nix` 的 tmux extraConfig 删了两类死行:

- `set -q -g status-utf8 on` / `setw -q -g utf8 on`:这两个选项 tmux 2.2
  (2018 年)就移除了。仓库里所有机器的 tmux 都来自 nixpkgs,是 3.x,这两行只会
  报 unknown option(所以当初加了 `-q` 把报错按掉),留着没有任何收益。
- `set -g prefix C-b` / `bind C-b send-prefix`:把默认值(
  `programs.tmux` 的默认 prefix 就是 C-b)显式写了一遍,删掉行为不变。

顺带,escape-time / focus-events / history-limit / base-index / mode-keys 五项
改写成 home-manager 原生选项(`escapeTime` / `focusEvents` / `historyLimit` /
`baseIndex` / `keyMode`),extraConfig 里只留没有原生选项对应的部分。

---

## 2026-09-03 · WSL 的默认模型名给 262K,84K 作为 fast 档 {#wsl-ninfer-default-262k}

公开 API 的 `qwen3.8-27b` 指向 groupwise-int 权重、NVFP4 KV、262K context、
Vision4K 和 MTP3,也是 NixOS 自动启动的常驻档。原生 NVFP4 权重的 84K 配置保留为
`qwen3.8-27b-fast`,它有更快的 Prefill 和更大的 Vision8K 预算。用户显式选择让最大
上下文成为无后缀默认值;因此客户端只在更看重速度或图片预算时才需要换模型名。

两档不能同时驻留显存,由 llama-swap 在收到请求时自动停止旧 OCI unit、启动目标
unit。API 地址始终是 Tailnet 的 `100.64.0.14:8000`,切换不要求客户端改 base URL。
完整内存账见 `docs/incidents.md#wsl-ninfer-24g`,网关链路见
`docs/incidents.md#wsl-ninfer-model-gateway`。

---

## 2026-09-01 · rpi4 从 portal 改成 bridge {#rpi4-portal-to-bridge}

rpi4 原本是六台 portal 之一:国内客户端连它的 `client-in2`(54322),流量经反向
隧道到 gizmo,从日本出去。搬到悉尼之后这个身份**已经名存实亡**,只是没人去
删 —— 它在 hotspot 的 NAT 后面,没有任何公网入口;`ddns-go` 也早关了,而
`rpi4.imdomestic.com` 还留着一条指向它国内旧地址的 AAAA。

于是在此之前的一段时间里,gizmo 一直在重试拨一条死链
(`rpi4.imdomestic.com:2444`),订阅里有一个连不上的节点,dae 的 `im` 组里也有
一个死节点在参与选路。这次一并删掉。

**改成 bridge 而不是修好 portal,是因为 portal 这个角色它当不了。** Xray 反向
代理的两端分工是固定的:portal 是有公网入口、被拨的那端;bridge 是主动拨出去
的那端,不需要任何入站可达性。悉尼这条线正好只满足后者 —— 这也正是 gizmo 一直
用 bridge 的原因,它挂在 NTT 消费线上,同样没有稳定公网入口。

所以现在有两条反向隧道,方向一致(国内 portal ← 境外 bridge),出口不同:

- `reverse-<h>.hank.internal` → gizmo(日本),客户端口 54322
- `reverse-<h>-au.hank.internal` → rpi4(悉尼),客户端口 54324

**只接 h610 和 sh 两台。** 其余几台 portal(r5s / r6s / r2s)的 ddns-go 只发
AAAA,而悉尼那条线没有 IPv6,拨不过去 —— 加进去只会再造几条死链。

## 2026-09-01 · 两个出口各有自己的自动组,绝不合并 {#au-exit-separate-auto-group}

每个客户端里是**两个**自动测速组,不是一个:

| | 日本出口 | 悉尼出口 | 手动选择组 |
|---|---|---|---|
| clash / imsub | `auto-jp` (url-test) | `auto-au` (url-test) | `im` (select) |
| Egern | `AUTO-JP` (smart) | `AUTO-AU` (smart) | `PROXY` (select) |
| mihomo | `auto-jp` | `auto-au` | `im` (select) |
| sing-box | `auto-jp` (urltest) | `auto-au` (urltest) | `im` (selector) |
| dae | `im` 组 | `au` 组 | 无(靠 routing 规则指) |

**组内自动择优,跨出口只手动切。** 理由是自动组比的全是延迟,而这两条线上
延迟和吞吐是**反的**。同一台 h610、同一时刻、同一目标实测:

| 目标 | 日本出口 54322 | 悉尼出口 54324 |
|---|---|---|
| AARNet 镜像(在悉尼) | **39 Mbps** | 13 Mbps |
| Cloudflare | **132 Mbps** | 18 Mbps |

连目标就在悉尼的时候,日本出口都快 3 倍。而同一时刻 dae 的延迟检查里,悉尼组
是 446–564ms 且稳定,日本组在 0.7–2.9s 之间反复判死判活 —— **按延迟看悉尼明显
更优,按吞吐看它差 3 到 7 倍**。合成一个自动组,悉尼会稳定胜出,然后把一切拖垮。

所以悉尼出口的定位是**冗余 + 一个澳洲 IP**,不是性能。要用澳洲 IP 或者日本那条
挂了,手动切 `auto-au`;平时留在 `auto-jp`。

dae 那边还有一个额外的坑值得单独记:`im` 组是靠 `name(keyword: 'imdomestic')`
筛的,所以那两个节点在 dae 里**故意不叫 `imdomestic-*`**,叫 `au-h610` /
`au-sh`。哪天有人为了"统一命名"把它们改回去,它们会**静悄悄地**混进 im 组,
不报任何错。

隧道段的带宽数据见 docs/incidents.md#syd-jp-relay-beats-direct。

---

## 2026-08-31 · rpi4 摘掉 dae {#rpi4-drop-dae}

这台搬到悉尼之后 dae 是**净损害**,所以从 `imports` 里摘了。另外八台
(shanghai/tank/x470/h310/h610/r2s/r5s/r6s)照旧,它们在国内,那套规则是对的。

那套规则的前提是「人在国内,需要翻墙出去」:`fallback: im`,而 im 组是经
六个国内 portal 的反向隧道到 gizmo(日本)。人到了悉尼,这个前提整个翻转:

**公寓网络的国际线路极好。** 本地有 Google Global Cache —— `ping
www.google.com` 是 **0.7ms**(走 IPv6,`2001:4860:...`),1.1.1.1 / 8.8.8.8
同样 0.7ms 左右,Telstra 悉尼 1.1ms 作参照。国际主流服务基本是本地落地的。

**而 dae 把这条线路绕成了 悉尼 → 国内 portal → 日本 → 目标。** 同一时刻
的 A/B(规则里 Apple/Microsoft 判 direct、Google/GitHub 判 im,四个都是
国外站):

| 目标 | dae 判定 | `curl` total |
|---|---|---|
| apple.com | direct | 0.12s |
| microsoft.com | direct | 0.27s |
| google.com | im | 2.90s |
| github.com | im | 3.91s |

**10 到 30 倍。** 注意 `time_connect` 看不出来(5~7ms),因为透明代理的 TCP
握手是和本地 dae 完成的 —— 只有 `time_total` / `time_starttransfer` 才暴露
真实路径,拿 connect 时间判断代理健康度会得出完全相反的结论。

到国内确实慢(晚高峰 `sh.imdomestic.com` 452ms),但那是上游 Superloop 的
transit 决定的,不是 dae 能救的 —— 恰恰相反,im 组要先绕回国内再去日本,
比直连更远。那条路的形状见 docs/incidents.md#syd-cn-route-via-europe。

## 2026-08-31 · rpi4 不再拨 PPPoE,ddns-go 也停了 {#rpi4-drop-pppoe}

这台 2026-08-31 从国内搬到悉尼的公寓,上游性质彻底变了:原来是自己拨号
(`services.pppd` 的 `chinamobile` peer,PPPoE over `enp1s0u2`),现在是插墙口吃 DHCP,
再过一道 captive portal。

**删掉的:**

- `services.pppd` 整块。PPPoE 的凭据是运营商宽带账号,换了国家就没有对应的东西了;
  留着一份拨不上的 peer 只会让 `maxfail 0 / holdoff 5` 无限重试刷日志。
  WAN 现在是 `20-wan-uplink` 里的 `DHCP = "yes"`,认证交给
  `my.captivePortal`(表单怎么来的见 docs/incidents.md#rpi4-sydney-captive-portal)。
- `25-wan-ppp` 那份 network。它 match 的 `ppp0` 不会再出现。
- `30-br-lan` 的 `IPv6SendRA` / `DHCPPrefixDelegation`。这两个原来是把 PPPoE 拨到的
  `::/60` 往 LAN 分一段,而公寓 hotspot 只给一个 NAT 后的 v4 地址,没有前缀委派。

**停掉但没删的:** `ddns-go`。它盯的 `netinterface: ppp0` 已经不存在,而且这台现在
整个在 hotspot 的 NAT 后面 —— WAN 地址是 `172.24/16`,也没有全局 IPv6,
把这种地址推到 `rpi4.imdomestic.com` 毫无意义。配置整份留在文件里,
`enable`/`wantedBy` 两行翻回来就能恢复,所以没必要为了"干净"把它删了再抄回来。

**连带失效、但这次没动的:** `services.xray` 的两个 inbound(2444 / 54322)和
wireguard 的 `10.0.0.6` —— 在 NAT 后面收不到入站连接。它们只是白监听,不报错也不
拖别的东西下水,等确定这台在悉尼要扮演什么角色再一起处理,不在这次改动范围里。

## 2026-08-31 · 删掉 LS_COLORS {#drop-ls-colors}

`home.sessionVariables.LS_COLORS` 原来是一条 1.8k、115 条规则的字符串,来自
trapd00r/LS_COLORS,当年连同别人的 dotfiles 一起原样抄进来的,从来没有人按自己
的口味改过一条。

**它自带一套 256 色板,和终端主题是脱钩的。** 里面写死的是 `38;5;40`(#00d700
绿)、`38;5;220`(#ffd700 黄)、`38;5;208`(#ff8700 橙)这类立方色号,不走终端
的 16 色调色板 —— 终端主题怎么换,这些颜色都纹丝不动。

**净收益经不起量:** 拿 30 个文件的样本树用 eza 实测,不设 LS_COLORS 时 21 个
文件有颜色、且全部落在终端调色板上;设了之后 22 个有颜色,其中 6 个
(`*.7z` / `*.tar.gz` / `README.md` / `LICENSE` / `*.sh` / 断链)是上面那套板外
硬编码色。也就是多点亮一个文件,换来六个游离在主题之外的颜色。

**最初的误判是以为它管 `ls`。** 实际的消费者是 eza(`ls` 别名和 chpwd hook)、
zsh 补全、fzf-tab、nushell;GNU `ls` 在这台机器上根本没人调用。而 eza 在
LS_COLORS 缺席时会退回自己的默认配色,用的是基本 ANSI 码 —— 所以删掉不是变成
没颜色,是变成跟着主题走的颜色。

同时删掉 `init-extra.zsh` 里的 `zstyle ':completion:*' list-colors
${(s.:.)LS_COLORS}`:值没了之后这条只会把补全菜单的颜色设成空,留着是误导。

---

## 2026-08-12 · 删掉 cockpit {#drop-cockpit}

**在 NixOS 上它 15 个页面里大部分没有后端。** h610 上实测 `pkcon` / `nmcli` /
`udisksctl` / `sosreport` / `setenforce` 全部 MISSING,于是 apps、packagekit、
networkmanager、storaged、sosreport、selinux 六页全是死的。剩下能用的
shell / systemd / metrics 三页,这个 fleet 里分别有 ssh、node_exporter 的
systemd collector、和 Prometheus 做得更好。

**users 页更糟,而且是理念相反而不是打包问题。** 全 fleet `mutableUsers = true`,
在 cockpit 里改一个 `users.users` 声明过的用户,下次 switch 会被静默改回去 ——
不报错,就是没了。cockpit 的前提是「用 GUI 改一台可变的机器」,NixOS 的前提是
「改配置再重建」。

**实际使用情况印证了这一点:** h610 和 r6s 早就各自 `mkForce false` 掉了,而还
开着的 r5s / shanghai 三十天日志零条。

**它还是「服务只绑 tailscale」这条规矩的唯一例外**,而且三个最不该例外的选项凑齐
了:`openFirewall = true` + `allowed-origins = ["*"]` + `AllowUnencrypted = true`,
实测监听在 `[::]:9090`。而 r5s 有 WAN + PPPoE、shanghai 是公网 VPS,两台都
`firewall.enable = false`。对比 `modules/telemetry/default.nix` 里那条「绑定地址
是唯一真正起作用的边界」。

**遗留:** Prometheus 当初为它让到 9009(见 `modules/monitoring` 的 port 选项)。
那个理由现在不成立了,但 9009 已经写进两份配置和看板,不值得再挪回去。

---

## 2026-08-12 · rpi4 上清掉 niri + firefox 桌面栈 {#rpi4-drop-desktop}

树莓派是那个 LAN 的网关(`192.168.20.1`),没接显示器,那套桌面栈**从来没人用
过** —— 纯历史遗留。

它当时拖进 system closure 的东西(实测 narSize):

| 包 | 大小 | 怎么进来的 |
|---|---|---|
| mbrola-voices | 645 MiB | etc → speech-dispatcher → mbrola → voices |
| llvm-21.1.8-lib | 532 MiB | tmpfiles → graphics-driver.conf → mesa → llvm |
| firefox-unwrapped | 356 MiB | system-path → firefox |
| nautilus | 277 MiB | etc → dbus-1 → nautilus |
| mesa | 260 MiB | graphics-drivers |
| speech-dispatcher + flite | 120 MiB | |

645 MiB 的语音合成音色库,在一台当路由器用的树莓派上 —— 那是 niri 带的
xdg portal / a11y 那一串的末端。

**配置里留下的 `gdm`/`gnome` 两个显式 `false` 是有意的:** 它们是「这台不要桌面」
的意图声明,不是对某个 profile 的覆盖(rpi4 的 profile 列表里 desktop 本来就是
注释掉的)。真有人哪天手滑加回 desktop profile,那两行会挡一下。
