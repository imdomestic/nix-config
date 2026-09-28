# Hank 的两行 buffer 顶栏

自写插件源码在 `pkgs/hank-tabline/`，通过 `vimUtils.buildVimPlugin` 打包，
由 `home/modules/nixvim/hank/default.nix` 的 `extraPlugins` 安装；不再加载
`mini.tabline`。这是一份插件实现，不是复制进仓库的个人 Lua 配置。
VS Code 的嵌入 Neovim 不加载此插件。

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

顶栏全宽置顶，Explorer 和正文都从它下面开始。Snacks Explorer 每次布局
会重新应用自身的窗口选项，所以 `on_show` 把根窗口的 `winbar` 留白同步进
Snacks 选项，再由 Snacks 自己计算子窗口大小。不移动它的浮窗，不接管
`on_update`，也不修改其窗口高度。

标签行左侧固定显示实心文件夹图标和当前 tabpage 工作目录的项目名，按内容宽度显示，
不加竖线或补齐空格，与首个 buffer 名之间留两格。切换文件、开关或调整 Explorer
不改变它的位置。长名称截短，最多占终端四分之一宽度；只有 buffer 标签参与横向滚动和点击切换。

配色直接读取 Evergarden 当前 palette：绿色选中背景与轨道、crust 色选中文字、
overlay2 色非选中文字、overlay0 色轨道、base 色底色。修改状态显示 `●`，
重名文件补路径，长标签按屏幕字符宽度裁切，文字中的 `%` 转义后交给 tabline。

## 验证

`pkgs/hank-tabline/tests.py` 需要 Python `pynvim` 和 Neovim 0.12+，会启动隔离
UI 实例检查两行渲染、鼠标点击、修改标记、Unicode/溢出、分屏和退出行为。
可通过 `--nvim /path/to/nvim --init /path/to/evaluated-init.lua` 验证完整配置，
同时覆盖固定项目名、目录变化、Explorer 位于顶栏下方、侧栏宽度变化、终端缩放、两行点击、
tabpage 切换、侧栏关闭和 Picker/LazyGit；不传参数时使用无配置 Neovim。
`--capture-explorer-json /tmp/sidebar.json` 可导出真实 UI 字符与配色作视觉检查。
