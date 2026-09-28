# 侧栏面板

自写插件 `pkgs/hank-panels/`，和顶栏插件一样通过 `vimUtils.buildVimPlugin`
打包。它只做三件事：

1. 登记面板：每个面板说明自己在哪一侧、怎么打开、怎么关闭、现在是否打开。
2. 同一侧同时只开一个：打开一个面板前，先关掉同侧已开的那个。
3. 给 [顶栏](nvim-tabline.md) 提供图标分组：`section("left")` / `section("right")`。

面板的位置和宽度仍由各插件自己的设置决定，这里不移动窗口。为什么没有交给
edgy.nvim，见 `docs/decisions.md#no-edgy`。

## 现有面板

| id | 侧 | 插件 | 快捷键 | 宽度设置在 |
|---|---|---|---|---|
| `explorer` | 左 | Snacks explorer | `<leader>e` | `snacks.settings.picker.sources.explorer` |
| `git` | 左 | Snacks `git_status`（侧栏布局） | `<leader>G` | 面板定义里的 `opts.layout` |
| `outline` | 左 | aerial.nvim | `<leader>o` | `plugins.aerial.settings.layout` |
| `database` | 左 | vim-dadbod-ui（仅 dev） | `<leader>D` | `globals.db_ui_winwidth` |
| `infoview` | 右 | lean.nvim infoview（仅 dev） | lean.nvim 自带 | `plugins.lean.settings.infoview` |

左侧四个统一 30 列，切换时正文不跳。`infoview` 只在当前 tabpage 里有 Lean
buffer（或 infoview 本身）时才出现在顶栏右端；lean.nvim 按 filetype 懒加载，
没加载时这个面板不存在。

图标用 Material 的实心 / 空心成对码位：打开时实心、关闭时空心。git 分支图标
没有空心版，两种状态同形，只靠颜色区分。粗体对 Nerd Font 图标无效（各字重里
是同一份字形），所以状态只能靠形状和颜色。

## 加一个面板

面板定义在 `home/modules/nixvim/hank/default.nix` 的 `panels.setup` 里。
`hank-panels.adapters` 提供三种现成的适配器：

- `window({ ft, open })`：插件自己开一个固定 filetype 的 split（aerial、dbui）。
  「是否打开」看当前 tabpage 里有没有该 filetype 的普通窗口，关闭时直接关窗。
- `snacks({ source, opts })`：Snacks picker 以侧栏布局常驻。`opts` 原样传给
  `Snacks.picker.pick`；想要侧栏形态需要 `layout.preset = "sidebar"`、
  `auto_close = false`、`jump.close = false`。
- `lean_infoview({})`：lean.nvim 每个 tabpage 一个 infoview，默认放在右侧。

也可以不用适配器，直接给出 `id`、`icon`、`open`、`close`、`is_open`，
可选 `side`（默认 `"left"`）、`icon_inactive`、`available`。图标可以写成码位
数字（`0xf024b`）或字符串。

## 在侧栏里切换

焦点在某个面板里时，`]b` / `[b` 在**同一侧**的面板之间轮换（首尾相接，
支持计数），而不是 `:bnext` —— 否则文件会被换进侧栏窗口。焦点在普通窗口时
仍然是 `:bnext` / `:bprevious`。判断「当前窗口属于哪个面板」靠适配器的
`owns(win)`：Snacks 侧栏检查 picker 的根窗口和各子浮窗，`window` 适配器看
filetype，infoview 看它记下的窗口 id。

面板在打开前会先回到一个普通文件窗口，因为 aerial 和 infoview 都附着在「当前
buffer」上；从另一个侧栏里点开时，它们否则会附着到侧栏自己的 buffer。

## API

```lua
require("hank-panels").toggle(id)  -- open / close / is_open(id) 同理
require("hank-panels").at(win)     -- 拥有该窗口的面板（默认当前窗口），没有则 nil
require("hank-panels").cycle(step) -- 侧栏内轮换；不在侧栏里返回 false
require("hank-panels").section(side) -- 交给 hank-tabline 的分组
```
