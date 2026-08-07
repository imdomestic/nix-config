# Alex：把 macOS 账户从 `ztymac` 改为 `kenneth`

本手册对应 `nixos/hosts/alex/`。目标短用户名按前文确定为
`kenneth`；如果最后确实想用 `keneeth`，不要照此执行，先把仓库里的
用户名统一改掉。

Apple 支持原地修改账户短名和 Home 目录。这样 UID、登录密码和原账户
数据都保留，比新建账户后手工复制整个 Home 更少产生权限问题。操作错误
可能导致无法登录，所以先保留一个独立管理员账户和可验证的备份。

Apple 官方步骤：<https://support.apple.com/en-ie/102547>

仓库中已经存在的 nixvim、Zsh、WezTerm、Starship、tmux 等配置继续复用。
本次只补了 `alex` 主机、Ghostty、Git/LFS、OrbStack/Conda 的最小 shell
集成，以及 Homebrew 顶层包。Clash 订阅、SSH 私钥、API key、Copilot/
Claude/Codex 登录态、浏览器数据、历史、缓存和数据库属于秘密或可变状态，
不会迁入 Git。

## 1. 改名前

1. 完成一次 Time Machine 或等价的完整备份，并确认备份可见。
2. 在“系统设置 → 用户与群组”新建一个临时管理员，例如
   `migration-admin`。不要用待改名的账户执行后续步骤。
3. 提交或另行备份当前工作区；改名会把本仓库随 Home 目录一起从
   `/Users/ztymac/.config/nix-config` 移到
   `/Users/kenneth/.config/nix-config`。
4. 如果 Home 目录正在通过“文件共享”共享，先停止共享。

可以先记录当前身份，改名后用同一组信息核对：

```sh
id
dscl . -read /Users/ztymac UniqueID NFSHomeDirectory UserShell
tmutil latestbackup
```

## 2. 原地改名

1. 完全退出 `ztymac`，登录刚创建的临时管理员。
2. 在 Finder 选择“前往 → 前往文件夹”，输入 `/Users`。
3. 把 Home 文件夹 `ztymac` 改名为 `kenneth`；不要复制文件夹，也不要
   新建一个空的 `/Users/kenneth`。
4. 打开“系统设置 → 用户与群组”，按住 Control 点击原账户，选择
   “高级选项”。
5. 把“用户名”（不是显示用的“用户”或“全名”）改为 `kenneth`。
6. 把“个人目录”改为 `/Users/kenneth`。不要修改 UID、主群组、登录
   shell 或其他高级字段。
7. 确认后重启，登录 `kenneth`。

账户密码不会因为短名变化而改变。电脑名则是另一项设置，本仓库会把它
声明为 `alex`。

## 3. 登录后先验证

在执行任何 Nix 激活前确认账户仍是原 UID、Home 可写：

```sh
id
test "$(id -un)" = kenneth
test "$HOME" = /Users/kenneth
test -O "$HOME" && test -w "$HOME"
dscl . -read /Users/kenneth UniqueID NFSHomeDirectory UserShell
```

不要预防性地对整个 Home 执行 `chown -R`。原地改名保留 UID，正常情况
下所有权会自然保持；只有验证发现具体异常时，才修复具体路径。

查找仍引用旧绝对路径的可读配置：

```sh
rg -l '/Users/ztymac' \
  ~/.config ~/.gitconfig ~/.zprofile ~/.zshenv ~/.zshrc 2>/dev/null
```

Codex Desktop 的 `~/.codex/config.toml` 同时包含插件缓存、项目记录和
运行时路径，改名后让应用自行刷新这些动态项，不要把整个文件做成只读的
Home Manager 链接。登录态、历史、数据库、Clash 订阅和 API key 也不进
Git。

## 4. 激活 `alex` 的 Nix 配置

先按仓库规则检查远端和本地漂移：

```sh
cd ~/.config/nix-config
git fetch
git status --short --branch
git log --oneline HEAD..origin/main
```

新文件在加入 Git 前不会被 flake 看见。先检查本次 diff，再至少把
`nixos/hosts/alex/`、`home/users/kenneth/alex.nix` 以及本次修改的注册文件
加入一次提交，然后才使用下面的 `.#alex` 配置。

如果远端有新提交，先决定 pull/rebase；不要直接 rebuild。首次启用
`alex` 时系统输出与当前 generation 不同是预期的，但仍应先看 dry build
会改什么：

```sh
readlink /run/current-system
nix build --dry-run .#darwinConfigurations.alex.system
just hm-dry alex kenneth
```

确认后分两次激活。系统和 Home Manager 是两个独立 closure：

```sh
just darwin alex
just hm alex kenneth
```

第一次 Home Manager 激活带 `-b backup`，会把它接管的旧 dotfile 改名为
`*.backup`，而不是覆盖。重开终端后检查 `hostname -s`、`git config
user.name`、Ghostty、Neovim 和常用命令，再保留临时管理员至少几天。确认
FileVault 解锁、iCloud、钥匙串、SSH、开发工具和应用都正常后，才考虑删除
临时管理员；不要在同一天删除回滚入口。
