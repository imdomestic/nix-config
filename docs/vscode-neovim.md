# Hank 的 VS Code / Neovim 配置

入口在 `home/modules/nixvim/hank/`：

- `default.nix`：终端 Neovim；linwhite 和 kenneth 仍导入这份基线。
- `editing.nix`：两边共享的 leader、搜索习惯、surround、Flash 和 Tree-sitter 文本对象。
- `vscode.nix`：独立 nixvim 包，只加载共享编辑功能，并把 IDE 操作交给 VS Code。
- `snippets/`：Rust `cp` / `cpi` 模板，两边复用。

Home Manager 接线在 `home/modules/vscode/`，目前只在 m1elite 的 hank home
启用 `my.vscode.enable`。macOS 使用已有的 `/Applications/Visual Studio Code.app`，
只增加 `code` 命令包装器，不额外安装第二份应用。这个包装器也让 Home Manager
在扩展集合变化时调用原生 CLI 刷新扩展索引；`package = null` 会跳过这一步，
已有用户目录可能发现不了新增的扩展。其他平台启用时使用 Home Manager 默认的 VS Code 包。

## GUI 修改怎样保留

仓库通过 `hank.nixvim-defaults` 本地扩展的 `configurationDefaults` 提供设置默认值，
通过 `contributes.keybindings` 提供快捷键默认值。扩展由 Nix 属性生成，再通过
`programs.vscode.profiles.default.extensions` 安装。

`programs.vscode.profiles.default.userSettings` 和 `keybindings` 保持为空。
Home Manager 不生成、不覆盖、不合并用户的 `settings.json` / `keybindings.json`。
扩展目录保持可写，可以继续从 GUI 安装其他扩展。

- GUI 设置和快捷键覆盖扩展默认值，之后的 Home Manager activation 仍保留覆盖。
- 在 GUI 中重置设置，会回到仓库当前提供的默认值。
- 想把 GUI 试出的设置带到其他机器时，需要手动把它整理进仓库；不会自动写回 Nix。
- 若自己覆盖了 Neovim 可执行文件路径，该覆盖同样优先；重置这一项才能重新使用
  仓库生成的轻量包。不要把临时 `/nix/store` 路径抄进用户设置。
- Lua 内的 leader 映射仍在 `hank/vscode.nix` 修改。GUI Keyboard Shortcuts
  管理的是 VS Code 收到的按键，不会编辑 nixvim 的映射表。

依据：[VS Code configurationDefaults](https://code.visualstudio.com/api/references/contribution-points#contributes.configurationDefaults)
和 [键盘规则优先级](https://code.visualstudio.com/docs/configure/keybindings#_keyboard-rules)。

## 使用

按仓库的 freshness check 完成同步和漂移检查，并关闭日常 VS Code 窗口后：

```sh
just hm-dry m1elite hank
just hm m1elite hank
```

重启 VS Code，使其重新扫描扩展目录。不要同时启用 VSCodeVim (`vscodevim.vim`)
和 VSCode Neovim (`asvetliakov.vscode-neovim`)。
本次变更不安装各语言的 VS Code 扩展；Rust/Haskell/Nix 等语言服务可以从 GUI
按需安装。跳转、重命名、格式化等快捷键调用当前语言扩展提供的能力。

## 按键

`<leader>` 是空格。

| 按键 | VS Code 动作 |
| --- | --- |
| `<leader>ff` / `<leader>f<space>` / `<leader>fr` | Quick Open：文件和历史记录 |
| `<leader>fb` | 所有打开的编辑器 |
| `<leader>fw` / `<leader>fs` | 内容搜索 / 工作区符号 |
| `<leader>fk` | GUI 快捷键设置 |
| `<leader>e` / `<leader>g` | 文件树 / Source Control |
| `[b` / `]b` | 当前组的上一个 / 下一个标签 |
| `<leader>c` / `<leader>q` / `<leader>Q` | 关闭当前 / 当前 / 全部编辑器；保留未保存提示 |
| `<leader>w` | 保存 |
| `Ctrl-h/j/k/l` | 左 / 下 / 上 / 右导航，包含编辑器组、侧栏和面板 |
| `Ctrl-w v` / `Ctrl-w s` | 向右 / 向下分屏 |
| `Ctrl-↑/↓/←/→` | 增加高度 / 减少高度 / 减少宽度 / 增加宽度 |
| `Ctrl-o` / `Ctrl-i` | 跳转历史后退 / 前进 |
| `Alt-m` | 切换终端；终端内也可用 |
| `gd` / `gD` / `gr` / `gi` / `gh` / `K` | 定义 / 声明 / 引用 / 实现 / 类型层次 / Hover |
| `<leader>lr` / `<leader>la` / `<leader>lf` | 重命名 / Code Action / 格式化 |
| `<leader>ld` / `<leader>lD` | Hover 诊断 / Problems |
| `<leader>lH` | 切换 inlay hints，写入可在 GUI 修改的用户设置 |
| `<leader>/` | 注释当前行或选区 |
| `[c` / `]c` | 上一 / 下一处 Git 改动 |
| `<leader>hs` / `<leader>hr` | 暂存 / 还原选中行的改动 |
| `<leader>hS` / `<leader>hu` / `<leader>hd` | 暂存文件 / 取消暂存文件 / 打开 diff |

编辑区中的导航映射只在 Normal 模式生效，保留插入模式原有的编辑按键。
在 Quick Open 中，`Ctrl-j/k` 选择下一/上一项。侧栏和终端中使用扩展默认快捷键；
普通输入框内保留输入行为。OS 窗口管理器若抢占了某个按键，仍需在 OS 侧处理。

`s/S/r/R` 使用 Flash；`sa/sd/sr` 等使用 mini.surround。
`af/if/ac/ic` 选择函数/类，`]m/[m/]]/[[` 移动到函数/类；这些功能保留
Tree-sitter 解析器，但 VS Code 内的高亮、缩进、折叠由 VS Code 处理。
OSC 52、终端 UI、补全、LSP 和 session 插件不会在嵌入实例中加载。

`<leader>fi`、`<leader>fu`、数据库 UI、Neovim 专属 Git 弹窗等没有直接映射。
`<leader>fr` 使用 Quick Open 的历史记录，不承诺复刻 Snacks recent 的筛选和排序。

## 验证

```sh
scripts/test-vscode-neovim.sh hank@m1elite
```

脚本构建声明的扩展并启动独立的 VS Code 测试窗口，使用临时用户目录、扩展目录和
测试文件。不会改动日常 VS Code 配置；窗口结束后打印结果，保留临时目录供查日志。
找不到应用时可通过 `VSCODE_BIN` 指定 CLI。需要桌面会话，不是 headless CI 测试。

2026-09-28 在 m1elite 上验证：VS Code 1.139.1、vscode-neovim 1.19.0、
Neovim 0.12.4。用户设置覆盖与重置、47 个桥接命令注册、横向/纵向分屏和导航、
标签切换、surround 编辑与 undo、Tree-sitter `daf`、inlay hints 切换及 Quick Open
调用通过。嵌入实例使用 VS Code 剪贴板，未加载终端 LSP、Snacks、Blink 或 Noice。
终端配置启动检查、42 份 Home 配置求值通过。测试不代表每个语言扩展的功能验收。
