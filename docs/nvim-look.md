# 界面分层

Neovim 界面的外观规则。终端里没有字号、圆角和阴影，只有字符格和颜色，所以
分区靠底色，焦点靠一个强调色，细节靠半格字符。配置在
`home/modules/nixvim/hank/default.nix`，颜色全部从 Evergarden 当前调色板取
（`evergarden.setup` 的 `editor` 开关加 `overrides` 函数），换色板不用改规则。

## 角色

| 角色 | 调色板 | 用在哪 | 高亮组 |
|---|---|---|---|
| 正文 | base | 编辑窗口 | `Normal`、`WinSeparator`（前景背景都是 base，分隔线留空） |
| 退后 | mantle | 侧栏、底部面板、顶栏的侧栏区块和底部页签、浮层里的详情（补全文档、签名、picker 预览） | `HankSunk`，边线 `HankSunkBorder`，标题 `HankSunkTitle` |
| 失焦 | base 与 mantle 各半 | 没有焦点的编辑窗口 | `NormalNC` |
| 浮起 | surface0 | 浮层：补全列表、picker 结果、which-key、LSP hover、诊断浮窗 | `NormalFloat`、`Pmenu`；`FloatBorder` 同色，边框成了一格留白 |
| 输入 | surface1 | 浮层里的输入行：picker 输入框、noice 命令行 | `HankField` |
| 底栏 | crust | 状态栏 | `StatusLine`、`MiniStatusline*` |

文字只有三级：正文、次要（subtext0：路径、说明、关键字）、淡（overlay0：行号）。
强调色（accent，绿）只用在「你在哪」和「你在找什么」：顶栏和底部页签的横线亮段、
光标行号、模式名、补全和 picker 的匹配字符。状态栏不用色块，模式只换字色。

## 半格边

小浮层（blink 的补全和文档、which-key、noice 命令行和它的补全列表）上下各用一行
`▄` / `▀` 收边：前景是浮层底色，背景是正文底色，看起来浮层上下各多出半格。对应
的组是 `HankEdgeRaised`、`HankEdgeSunk`、`HankEdgeField`。picker 的输入行两端用
`▐` / `▌`（`HankCapField`）收边。边框写成 8 个字符的数组，字符可以带自己的
高亮组，所以文档窗两侧的空白用 `HankSunk`，上下的半格用 `HankEdgeSunk`。

git 标记是贴着行号左侧的 `▎`，删除是贴底 / 贴顶的 `▁` / `▔`。

## Snacks 的侧栏和底部面板

Snacks 的所有 picker 共用一组高亮（`SnacksPickerList`、`SnacksPickerInput` …，
最后都落到 `NormalFloat`），浮动 picker 要浮起，而 explorer、git、问题列表这些
split 形态的面板要退后。picker 配置里写 `win.list.wo.winhighlight` 没有用：
Snacks 合并窗口选项时默认值优先。所以在 `on_show` 里调用
`require("hank-panels.adapters").snacks_surface(picker, winhl)`，只对 split 形态
的 picker 生效。它要改两处：

- 窗口对象的 `opts.wo`，以及 `layout.win_opts`。每次布局重排（比如
  `reserve_snacks` 调用的 `layout:update()`）都会从 `win_opts` 这份建窗时的快照
  重新合并子窗口选项，只改窗口对象会被冲掉。
- 根 split 的 `fillchars`。Snacks 给自己的窗口设了局部 `fillchars`
  （`eob: ,lastline:…`），没列出的 `vert` 回到默认的 `│`，侧栏和正文之间又出现
  分隔线。要拷全局值 `vim.go.fillchars`；在 `on_show` 里用 `vim.o` 读到的是
  Snacks 自己那个局部值。

Snacks terminal、noice 的消息列表、aerial、dbui、quickfix 各自用 `winhighlight`
把 `Normal` / `NormalNC` 映射到 `HankSunk`。`NormalNC` 也要映射，否则面板没有
焦点时会变成失焦色。

浮动 picker 用自定义布局 `hank`（终端不足 120 列时退回 Snacks 的 `vertical`）：
左边结果浮起、输入行在最上面、下面空一行，右边预览下沉。

## 没做的

- picker 遮罩（`backdrop`）仍然关着：打开时遮罩会跳过 explorer 的下层浮窗，
  遮罩下只剩空的侧栏容器。
- Snacks 通知框、lazygit 浮窗沿用自身布局；边框因为 `FloatBorder` 同色而成了留白。

## 验证

`pkgs/hank-tabline/tests.py` 覆盖顶栏、侧栏和底部面板的位置与切换，也检查开了
横线时当前标签不再是绿底块。颜色本身靠启动完整配置后读每一格的实际颜色核对：
侧栏和底部面板是 mantle，explorer 和正文之间的分隔列是空格。
