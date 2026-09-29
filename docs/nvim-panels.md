# 侧栏和底部面板

自写插件 `pkgs/hank-panels/`，和顶栏插件一样通过 `vimUtils.buildVimPlugin`
打包。它只做三件事：

1. 登记面板：每个面板说明自己在哪一侧（`left` / `right` / `bottom`）、怎么打开、
   怎么关闭、现在是否打开。
2. 同一侧同时只开一个：打开一个面板前，先关掉同侧已开的那个。
3. 给 [顶栏](nvim-tabline.md) 提供分组：`section("left")` / `section("right")`
   是顶栏两端的图标，只在该侧有面板打开时显示；`section("bottom")` 是底部面板
   顶上的页签（图标加文字），由 `window("bottom")` 告诉顶栏画在哪个窗口上。

面板的位置和尺寸仍由各插件自己的设置决定，这里不移动窗口。为什么没有交给
edgy.nvim，见 `docs/decisions.md#no-edgy`。

## 现有面板

| id | 侧 | 插件 | 快捷键 | 尺寸设置在 |
|---|---|---|---|---|
| `explorer` | 左 | Snacks explorer | `<leader>e` | `snacks.settings.picker.sources.explorer` |
| `git` | 左 | Snacks `git_status`（侧栏布局） | `<leader>G` | 面板定义里的 `opts.layout` |
| `outline` | 左 | aerial.nvim | `<leader>o` | `plugins.aerial.settings.layout` |
| `database` | 左 | vim-dadbod-ui（仅 dev） | `<leader>D` | `globals.db_ui_winwidth` |
| `infoview` | 右 | lean.nvim infoview（仅 dev） | lean.nvim 自带 | `plugins.lean.settings.infoview` |
| `problems` | 底 | Snacks `diagnostics`（底部布局） | `<leader>lD` | 面板定义里的 `opts.layout` |
| `terminal` | 底 | Snacks terminal | `<M-m>`、`<leader>th` | `snacks.settings.terminal.win.height` |
| `quickfix` | 底 | 内置 quickfix | `<leader>tq` | 面板定义里的 `copen` 行数 |
| `messages` | 底 | noice 消息列表 | `<leader>tm` | `noice.settings.views.split.size` |

左侧四个统一 30 列（`sidebarWidth`，顶栏左区块也用它），底部四个统一 12 行
（`bottomHeight`，含顶栏插件占用的 winbar 那一行），切换时正文不跳。底色统一为
`HankSunk`（mantle，比正文暗一级），和顶栏区块、底部页签连成一片，与正文区分开；
为什么 Snacks 的面板要单独处理，见 [界面分层](nvim-look.md)。

`infoview` 的图标只在 infoview 打开时出现在顶栏右端（和左侧一样：区块跟着
面板出现、消失）。它只在当前 tabpage 有 Lean buffer 时才算可用；lean.nvim
按 filetype 懒加载，没加载时这个面板不存在。

大纲在 nix 文件里靠 nil 的 documentSymbol：它把 attrset 的每个键都报成
`Field`，而 aerial 默认只显示类、函数、模块等几类，所以 `filter_kind` 对 nix
关掉过滤，其它语言保持默认。git 面板只有 30 列，默认的路径格式会把文件名本身
截掉，所以用 `filename_first`：文件名在前，目录跟在后面。

git 面板和问题列表都设了 `show_empty = true`。Snacks picker 默认在结果为空时
弹一条 No results 就关掉自己，工作区干净时 git 面板会一闪即逝，没有诊断时问题
列表打不开。

问题列表的页签带诊断总数（`Problems 3`），诊断变化时顶栏插件会重画。列表本身是
打开那一刻的快照，和 git 面板一样。

消息面板用 noice 的 `all` 而不是 `history`：`history` 按消息类型过滤，`:echomsg`
之类进不去，过滤后为空时 noice 不开窗口，只弹一条通知。noice 里一条消息都没有时
`all` 也一样打不开。

终端关闭时只是隐藏，shell 继续跑，下次打开还是同一个。

图标用 Material 的实心 / 空心成对码位：打开时实心、关闭时空心。git 分支、终端、
quickfix 没有空心版，两种状态同形，只靠颜色区分。粗体对 Nerd Font 图标无效（各
字重里是同一份字形），所以状态只能靠形状和颜色。

## 加一个面板

面板定义在 `home/modules/nixvim/hank/default.nix` 的 `panels.setup` 里。
`hank-panels.adapters` 提供四种现成的适配器：

- `window({ ft, open })`：插件自己开一个固定 filetype 的 split（aerial、dbui、
  quickfix、noice 的消息列表）。「是否打开」看当前 tabpage 里有没有该 filetype 的
  普通窗口，关闭时直接关窗。
- `snacks({ source, opts })`：Snacks picker 以 split 形态常驻（侧栏或底部）。
  `opts` 原样传给 `Snacks.picker.pick`；要常驻需要 `auto_close = false`、
  `jump.close = false`，通常还要 `show_empty = true`；侧栏用
  `layout.preset = "sidebar"`，底部在 `layout.layout` 里写 `position = "bottom"`。
- `snacks_terminal({ cmd?, opts? })`：Snacks terminal，默认放在底部；关闭时隐藏。
- `lean_infoview({})`：lean.nvim 每个 tabpage 一个 infoview，默认放在右侧。
- `snacks_surface(picker, winhl)`：不是面板定义，而是在 picker 的 `on_show` 里调用，
  让 split 形态的 picker 换一组窗口高亮（Hank 的配置用它换成 `HankSunk`）。

也可以不用适配器，直接给出 `id`、`icon`、`open`、`close`、`is_open`，
可选 `side`（默认 `"left"`）、`icon_inactive`、`label`（底部页签的文字，字符串
或函数，默认用 `id`）、`available`、`owns`。图标可以写成码位数字（`0xf024b`）
或字符串。

## 在面板里切换

焦点在某个面板里时，`]b` / `[b` 在**同一侧**的面板之间轮换（首尾相接，
支持计数），而不是 `:bnext` —— 否则文件会被换进面板窗口。焦点在普通窗口时
仍然是 `:bnext` / `:bprevious`。判断「当前窗口属于哪个面板」靠适配器的
`owns(win)`：Snacks picker 检查根窗口和各子浮窗，`window` 和终端适配器看
filetype，infoview 看它记下的窗口 id。

面板在打开前会先回到一个普通文件窗口，因为 aerial 和 infoview 都附着在「当前
buffer」上；从另一个面板里打开时，它们否则会附着到面板自己的 buffer。

## API

```lua
require("hank-panels").toggle(id)    -- open / close / is_open(id) 同理
require("hank-panels").at(win)       -- 拥有该窗口的面板（默认当前窗口），没有则 nil
require("hank-panels").window(side)  -- 该侧打开的面板所在的 split，没有则 nil
require("hank-panels").cycle(step)   -- 面板内轮换；不在面板里返回 false
require("hank-panels").section(side) -- 交给 hank-tabline 的分组
```
