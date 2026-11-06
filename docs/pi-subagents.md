# Pi 子代理与动态工作流

Hank 的 dev 档 Pi 安装 `@tintinweb/pi-subagents` 0.22.1，源码、依赖和版本由
`pkgs/pi-tintin-subagents/` 固定；Home Manager 通过
`home/hank/modules/pi/default.nix` 只生成 `hank-pi.ts` 一个扩展入口，由
`bootstrap.ts` 显式装配 CC、better-render、输入框、statusline 和子代理，不依赖
扩展文件名字排序。不运行 `pi install` 或自动更新，Kenneth、Linwhite 的 home 不受影响。

## 使用

Home Manager 激活后，在 Pi 中 `/reload`。`/agents` 打开管理菜单，能查看代理
类型、运行中的会话、工作流和设置；运行中的代理显示在输入框下方的 FleetView 中。
上方 Agents 树与重复的 running-agent 计数由 `subagents.ts` 显示适配器硬关闭，
即使项目设置覆盖 `widgetMode` 也不重新挂载。Workflow 工具结果默认只显示状态
摘要与规模警告，展开工具或 `/agents → Workflows` 才看完整树；下方保持
statusline → 提示 → main / 子代理的紧凑顺序，两格缩进与方向键导航不变。

可以直接用自然语言：

```text
让 Explore 找一下这个仓库中 SSH 策略的定义，只读调查，不修改文件。
让两个 Plan 子代理分别审查当前 diff 的正确性和测试覆盖，汇总后再告诉我。
用动态工作流先列出目标模块，再逐个审查，最后汇总；不要修改文件。
```

- `Agent`：主会话优先直接读文件、搜索、修改和验证；只有明确要求委派，或直接调查后
  确认一个较大的独立子任务确实受益于并行/上下文隔离时才使用。匹配代理类型、
  普通查文件、小修改、常规调试和“多一个 reviewer 更保险”不自动触发委派。
  获准的任务默认在后台运行；下一步必须等结果且无其他有效工作时才前台等待。
- `get_subagent_result`：获取后台结果；完成时也会通知主会话，不必循环查询。
- `steer_subagent`：运行中补充要求。也可通过 `/agents` 的会话查看器发送消息、停止代理。
- `SubagentWorkflow`：仅在用户明确要求 workflow 或多代理编排时，模型才编写
  `agent()` / `parallel()` / `pipeline()` 脚本；任务复杂、多阶段、审查或独立验证
  本身不算授权。在 `/agents → Workflows` 查看；不是 `/workflows` 命令。
- `@explore …`：直接指定代理。上游默认 `agentMentions = "model"` 会先让主模型的
  临时副本根据当前对话整理任务，因此有额外模型调用；可在设置中改为 `direct`，
  代价是只发送自己写的任务，不自动整理对话背景。

默认代理是 `general-purpose`、`Explore` 和 `Plan`。通用代理继承主会话系统指令；
Explore/Plan 使用独立的只读提示词，不继承整个仓库指令。Plan 和通用代理默认
继承主模型；Explore 优先 Haiku，没有可用的对应模型时回退到主模型。没有在
配置里硬编码新的模型路由或凭据，仍使用已有 `models.json` 和 CLIProxy/NInfer。

## 本仓库的默认设置

`home/hank/modules/pi/subagents-settings.nix` 声明的字段在激活时合并到
`~/.pi/agent/subagents.json`，保留未声明字段。项目的 `.pi/subagents.json`
优先于全局设置；`/agents → Settings` 写项目文件，而不是改 Nix store。

| 设置 | 值 | 含义 |
| --- | --- | --- |
| `maxConcurrent` | 100 | 普通后台代理池上限 |
| `maxConcurrentForeground` | 100 | 普通前台代理池上限，独立于后台池，不是合计最多 100 个 |
| `schedulingEnabled` | false | 不提供定时代理，不加载或启动计划任务 |
| `reportUsage` | true | 子代理用量进入主会话工具用量统计，现有状态栏费用可以计入 |
| `showCost` | true | 代理卡片和列表显示 Pi 按配置单价估算的费用 |
| `fleetView` | true | 保留下方可导航的 main / 子代理列表 |
| `widgetMode` | `off` | 关闭上方 Agents 树及其重复状态计数 |

后台费用通过后续工具结果上报，可能晚于代理完成时刻；不是账单实时余额。
子代理费用不会被算成主会话的上下文占用。模型没有价格数据时仍按现有配置计零。

**动态工作流不受上面两个并发池限制。** 上游使用独立的 CPU 数量相关并发上限，
最多 16 个同时运行、每次工作流最多 1000 个代理；不是费用预算。普通嵌套代理和
部分直接派发路径也不计入这两个池。普通池按用户要求放宽到 `100`；降低自动委派
频率靠主会话优先策略，不靠压低并发。不把 `100` 理解成全插件总上限或费用预算。

没有自动运行审查或研究。`subagents.ts` 替换插件原来的主动委派描述与规则，
不修改参数 schema、任务执行或通知协议；这是降低调用频率的模型策略，不是禁止
所有 Agent 调用的权限门。决定与显示边界见
[主会话优先策略](decisions.md#pi-subagents-main-first)。
插件本身保留每 60 秒一次的内存记录清理；有任务时
还有 UI 动画刷新，不会因此定时启动模型或执行 `git status`。状态栏的 Git
刷新仍是事件驱动。

## 文件与权限

子会话使用独立上下文，但通过 SDK **运行在同一个 Pi 进程**，不是 OS 沙箱。
Explore/Plan 虽然不提供 edit/write，仍有 Bash；只读意图不能当成文件系统权限隔离。
需要硬隔离时另用容器/虚拟机或工具权限控制。

- 子代理默认持久化 Pi 会话，支持续聊；临时 `.output` 转录位于系统临时目录。
- 自定义代理定义可放在 `~/.pi/agent/agents/` 或受信任项目的 `.pi/agents/`。
- 并行审查可以共享当前工作树；**并行写代码须分配不重叠范围或显式使用 worktree**。
  worktree 看不到当前工作树的未提交 diff，不能用于审查它。
- worktree 模式会在独立分支保存修改，可能自动创建本地提交；不会自动合并回主分支。
- `/reload` 或退出会停止当前代理和工作流。工作流 journal 是当前会话的临时恢复记录，
  不是跨 Pi 重启的持久任务系统。

CC 继续渲染普通工具，Agent 和工作流工具保留插件自己的卡片；正文仍交给
better-render，输入框和状态栏不替换。无界面子会话不会执行主窗口的 CC 生命周期，
也不会卸载其 better-render 补丁，见
[渲染生命周期回归](incidents.md#pi-subagent-renderer-lifecycle)。

## 验证

```sh
bash scripts/check-pi-subagents.sh
bash scripts/check-pi-render.sh
bash scripts/check-pi-ui.sh
nix eval --raw '.#homeConfigurations."hosts/praxic/hank".activationPackage.drvPath'
```

子代理测试使用当前 Nix Pi 的真实 SDK 会话和离线确定性 provider，覆盖原生 read、
只读工具范围、会话续跑、后台通知、用量去重、工作流 worker、取消和两轮加载清理。
渲染测试加载 Home Manager 实际生成的完整 bootstrap 入口，启动真实离线后台
子代理，检查输入框与 footer 单一归属、只有下方 FleetView、异步启动后的挂载顺序、
无 Magic Context 工具、主窗口补丁不被子会话退出清掉、公式、Markdown 与 reload 清理。
测试刻意写入项目 `widgetMode = "all"`，验证启动、工具事件及异步代理刷新仍不出现
上方树；另验委派提示词、Workflow 摘要/展开、规模警告与错误输出保留。
不调用付费模型、不激活 home；不能替代 Rex 中的实际键盘、鼠标及网络服务验收。

上游：[tintinweb/pi-subagents](https://github.com/tintinweb/pi-subagents)。
