# 界面分层

Neovim 界面的外观规则：窗口之间靠底色区分，焦点靠一个强调色。配置在
`home/modules/nixvim/hank/default.nix`，颜色全部从 Evergarden 当前调色板取
（`evergarden.setup` 的 `editor` 开关加 `overrides` 函数），换色板不用改规则。

浮层（补全、文档、签名、which-key、noice 命令行、Snacks 浮动 picker、诊断浮窗）
保持主题默认：mantle 底加圆角边框。为什么没有去掉边框，见
`docs/decisions.md#floats-keep-borders`。

## 角色

| 角色 | 调色板 | 用在哪 | 高亮组 |
|---|---|---|---|
| 正文 | base | 编辑窗口 | `Normal`、`WinSeparator`（前景背景都是 base，分隔线留空） |
| 退后 | mantle | 侧栏、底部面板、顶栏的侧栏区块和底部页签 | `HankSunk`，边线 `HankSunkBorder`，标题 `HankSunkTitle` |
| 失焦 | base 与 mantle 各半 | 没有焦点的正文窗口（只在正文窗口之间，见下） | `NormalNC` |
| 底栏 | crust | 状态栏 | `StatusLine`、`MiniStatusline*` |

文字只有三级：正文、次要（subtext0：路径、说明、关键字）、淡（overlay0：行号）。
强调色（accent，绿）只用在「你在哪」和「你在找什么」：顶栏和底部页签的横线亮段、
光标行号、模式名、补全选中竖条、补全和 picker 的匹配字符。状态栏不用色块，模式
只换字色。git 标记是贴着行号左侧的 `▎`，删除是贴底 / 贴顶的 `▁` / `▔`。

## 补全

补全菜单选中项左边有一格强调色的 `▎`（`HankSelBar`，底色同 `PmenuSel`）。blink
只在有选中项时打开菜单窗口的 `cursorline`，并把光标放在选中项上；
`BlinkCmpMenuOpen` 时给菜单窗口设 `statuscolumn`，它在被绘制的窗口里求值，光标行
且开着 `cursorline` 时画竖条。

命令行的补全列表是 blink 画的，位置取自 noice 公布的 `vim.g.ui_cmdline_pos`（输入
那一行）。blink 的 `cmdline_position` 在命令行浮在屏幕中间时把它往下挪一行，让
列表落在命令行浮层的下边框下面，而不是压在边框上；底部的命令行（`/` 搜索）不挪。

## Snacks 的侧栏和底部面板

Snacks 的所有 picker 共用一组高亮（`SnacksPickerList`、`SnacksPickerInput` …，
最后都落到 `NormalFloat`），explorer、git、问题列表这些 split 形态的面板要用
`HankSunk`，不能跟着浮层的颜色走。picker 配置里写 `win.list.wo.winhighlight` 没有
用：Snacks 合并窗口选项时默认值优先。所以在 `on_show` 里调用
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

## 失焦变暗只在正文窗口之间

焦点去了侧栏、底部面板或浮层时，最近用过的正文窗口不变暗：它的 `winhighlight`
里有 `NormalNC:Normal`，其它正文窗口照常用 `NormalNC`。不这样做的话，打开侧栏
（焦点进侧栏）时正文变暗，而侧栏和正文之间那一列是正文底色，颜色就接不上。
更新放在 `vim.schedule` 里：新开的侧栏 split 在换成自己的缓冲区之前会先短暂显示
当前文件，同步判断会把它当成正文窗口。

## 没做的

- picker 遮罩（`backdrop`）仍然关着：打开时遮罩会跳过 explorer 的下层浮窗，
  遮罩下只剩空的侧栏容器。

## 验证

`pkgs/hank-tabline/tests.py` 覆盖顶栏、侧栏和底部面板的位置与切换，也检查开了
横线时当前标签不再是绿底块。颜色本身靠启动完整配置后读每一格的实际颜色核对：
侧栏和底部面板是 mantle，explorer 和正文之间的分隔列是空格，焦点在侧栏时正文
不变暗。
