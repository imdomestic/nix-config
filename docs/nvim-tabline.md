# Hank 的顶栏

自写插件源码在 `pkgs/hank-tabline/`，通过 `vimUtils.buildVimPlugin` 打包，
由 `home/modules/nixvim/hank/default.nix` 的 `extraPlugins` 安装；不再加载
`mini.tabline`。这是一份插件实现，不是复制进仓库的个人 Lua 配置。
VS Code 的嵌入 Neovim 不加载此插件。

插件只负责画：一行由若干「分组」拼成的标签，外加可选的第二行横线。分组自己
提供条目，插件不关心条目代表什么。现在的分组从左到右是：

| 分组 | 来源 | 对齐 | 当前项样式 |
|---|---|---|---|
| 项目名（可选） | `hank-tabline.project` | 左，固定 | 绿色粗体文字，不可点击 |
| 左侧面板图标 | `hank-panels` 的 `section("left")` | 左，固定 | 实心绿色图标 |
| buffer 标签 | `hank-tabline.buffers` | 填满中间，可滚动 | 绿底块 |
| 右侧面板图标 | `hank-panels` 的 `section("right")` | 右，固定 | 实心绿色图标 |

面板图标见 [侧栏面板](nvim-panels.md)。

## 选项

三项都在 Home Manager 里切换，对应插件 `setup()` 的同名参数：

```nix
my.nixvim.tabline.underline.enable = true;  # 第二行横线，默认关
my.nixvim.tabline.animation.enable = false; # 横线滑动动画，默认开（只在横线开启时有意义）
my.nixvim.tabline.project.enable = true;    # 左端固定项目名，默认关
```

插件本身的默认值同上：`underline = false, animate = true, project = false`。

## 分组接口

`setup({ sections = { left = {...}, right = {...} } })` 接收分组表。每个分组：

- `items(ctx)`：返回 `{ id, text, active }` 列表；`ctx.columns` 是终端宽度。
  `text` 自带左右留白。
- `click(id, button)`：可选。没有它的分组整段不可点击。
- `style`：`"block"`（默认，当前项绿底块）、`"icon"`（只变色）、`"label"`。
- `pad`：横线亮段比条目两端各缩进多少格，默认 1；可以是半格（图标组用 0.5，
  亮段正好落在图标下方，两侧各留半格空）。
- `update()`：可选，每次刷新前调用（buffer 分组用它记住最近的正文窗口）。

固定分组先占左右两端，buffer 分组在剩下的宽度里滚动；打开或关闭侧栏、切换
面板都不会让 buffer 标签移动。

## Posting 源码对应

参考 Posting commit `a8373a4cec3893becd0e1bd9d42042d6dfbfe0ae`，它固定依赖
Textual 6.1.0。普通模式使用 Textual 的 `Tabs`；Posting 的 compact 模式才
把高度改成一行并隐藏 `Underline`。

- `Tab` 高一行，宽度按文字，左右各一格 padding。未选中文字使用低对比度颜色。
- `Tabs` 总高两行；焦点状态的 active tab 使用 block-cursor 的前景、背景和粗体。
- 第二行 `Underline` 占满宽度，用 `━`、`╸`、`╺` 绘制轨道和半格端点。
- 亮色段对齐 active tab 的文字区域，扣除左右 padding；切换动画为 0.3 秒。
- 点击标签或其下方横线均可切换；溢出时把 active tab 滚动至视野中间。
- Posting 给有焦点的 Tabs 增加 `h/l` 切换。Neovim 保留既有 `[b` / `]b`，
  不占用正文的 `h/l`；视觉上的 active 状态对应最近的正文窗口所显示的 buffer。

一条横线上可以同时有多段亮色：每个有当前项的分组各一段。两端都存在的段做
滑动动画，新出现的段直接出现在目标位置。

源码：[Posting 样式](https://github.com/darrenburns/posting/blob/a8373a4cec3893becd0e1bd9d42042d6dfbfe0ae/src/posting/posting.scss)、
[PostingTabbedContent](https://github.com/darrenburns/posting/blob/a8373a4cec3893becd0e1bd9d42042d6dfbfe0ae/src/posting/widgets/tabbed_content.py)、
[Textual Tabs](https://github.com/Textualize/textual/blob/v6.1.0/src/textual/widgets/_tabs.py)、
[Textual Bar](https://github.com/Textualize/textual/blob/v6.1.0/src/textual/renderables/bar.py)。

## Neovim 实现

第一行使用原生 `tabline` 和点击回调，第二行通过顶层窗口的 `winbar` 预留
空间，用一个不接受焦点的浮层绘制连续轨道。没有新增普通 split，正文第一行
不会被覆盖，`Ctrl-w`、`:only`、关闭最后一个窗口都维持正常行为。
只有最上方窗口需要预留行，下面的水平分屏不加空白行。过小的终端暂时隐藏
第二行。顶部已有的自定义 `winbar` 在预留期间让给轨道，窗口移至下方时恢复。

顶栏全宽置顶，侧栏和正文都从它下面开始。Snacks 每次布局会重新应用自身的
窗口选项，所以侧栏形态的 picker（Explorer、git 面板）要在 `on_show` 里调用
`require("hank-tabline").reserve_snacks(picker)`：它把根窗口的 `winbar` 留白
同步进 Snacks 选项，再由 Snacks 自己计算子窗口大小。浮动 picker 直接跳过。
不移动它的浮窗，不接管 `on_update`，也不修改其窗口高度。

项目名分组显示实心文件夹图标和当前 tabpage 工作目录的项目名，按内容宽度显示，
长名称截短，最多占终端四分之一宽度。

配色直接读取 Evergarden 当前 palette：绿色选中背景与轨道、crust 色选中文字、
overlay2 色非选中文字、overlay0 色轨道、base 色底色。修改状态显示 `●`，
重名文件补路径，长标签按屏幕字符宽度裁切，文字中的 `%` 转义后交给 tabline。

## 验证

`pkgs/hank-tabline/tests.py` 需要 Python `pynvim` 和 Neovim 0.12+，会启动隔离
UI 实例检查两行渲染、鼠标点击、修改标记、Unicode/溢出、分屏和退出行为。

不传 `--init` 时使用无配置 Neovim，并注册三个假面板（左侧两个、右侧一个），
检查点击图标开关、同侧互斥、两侧共存、点击横线切换，以及开关面板时 buffer
标签不移动。

`--nvim /path/to/nvim --init /path/to/evaluated-init.lua` 验证完整配置，额外覆盖
Explorer 位于顶栏下方、侧栏宽度变化、终端缩放、tabpage 切换、侧栏关闭、
Picker/LazyGit，以及从顶栏切换 Explorer 与 git 面板（须在 git 仓库里运行）。

`--underline`、`--project`、`--no-animate` 分别对应三个选项；验证完整配置时
这几个参数必须与该 init 的设置一致。`--capture-explorer-json /tmp/sidebar.json`
可导出真实 UI 字符与配色作视觉检查。

完整配置的 nvim 与 init 可以这样构建（开关选项用 `extendModules` 覆盖）：

```sh
nix build --no-link --print-out-paths \
  '.#homeConfigurations."hank@m1elite".config.programs.nixvim.build.package' \
  '.#homeConfigurations."hank@m1elite".config.programs.nixvim.build.initFile'
```
