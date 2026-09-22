# 决策记录

这里放**「某样东西为什么不在」**。

这类说明没有可以依附的代码行 —— 一个被删掉的服务、一个故意不开的选项,在配置里
是一片空白,而空白处贴不了注释。硬塞在附近某行上面只会让那行显得莫名其妙。

反过来,「这一行为什么这么写」应该留在那一行旁边,不要搬到这里。

按时间倒序。代码里用 `docs/decisions.md#<锚点>` 引用。

---

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
隧道到 r5sjp,从日本出去。搬到悉尼之后这个身份**已经名存实亡**,只是没人去
删 —— 它在 hotspot 的 NAT 后面,没有任何公网入口;`ddns-go` 也早关了,而
`rpi4.imdomestic.com` 还留着一条指向它国内旧地址的 AAAA。

于是在此之前的一段时间里,r5sjp 一直在重试拨一条死链
(`rpi4.imdomestic.com:2444`),订阅里有一个连不上的节点,dae 的 `im` 组里也有
一个死节点在参与选路。这次一并删掉。

**改成 bridge 而不是修好 portal,是因为 portal 这个角色它当不了。** Xray 反向
代理的两端分工是固定的:portal 是有公网入口、被拨的那端;bridge 是主动拨出去
的那端,不需要任何入站可达性。悉尼这条线正好只满足后者 —— 这也正是 r5sjp 一直
用 bridge 的原因,它挂在 NTT 消费线上,同样没有稳定公网入口。

所以现在有两条反向隧道,方向一致(国内 portal ← 境外 bridge),出口不同:

- `reverse-<h>.hank.internal` → r5sjp(日本),客户端口 54322
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
六个国内 portal 的反向隧道到 r5sjp(日本)。人到了悉尼,这个前提整个翻转:

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
