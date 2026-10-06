# Chorus：Mac → encore → seraph 开发指南

更新：2026-10-06。当前策略：**本地 commit only，不 push**。

## 1. 机器分工与源码位置

| 机器 | 职责 | 路径 |
| --- | --- | --- |
| Mac / aegis | SSH、终端、Moonlight 操作入口 | 无需维护第二份 chorus |
| encore | 唯一权威工作区、Git、Neovim/JDTLS、客户端渲染、Sunshine | `~/chorus` |
| seraph（原生 NixOS，9950X CPU） | Gradle 编译/测试、独立开发服务端 | `~/chorus-build`、`~/chorus-worker` |

Windows/WSL 的 `9950x` 暂不参与。seraph 实测 32 逻辑 CPU、30 GiB RAM；
远程入口默认 Gradle `--max-workers=8`，Nix `--max-jobs 2 --cores 4`。
这些限制不等于 JVM 总内存或所有子进程的硬上限。

`chorus-build` 和 `chorus-worker` 是可重新同步的工作副本，不含 `.git`。
**只在 encore 的 `~/chorus` 编辑、切分支、提交**。同步包括未提交的源码，
不需要 push。客户端、JDTLS 和本机源码缓存仍使用 encore 的 CPU；
`mc-build-remote` 才把指定 Gradle 任务放到 seraph，不是透明远程执行所有计算。

## 2. 本次验收记录

| 检查 | 结果 |
| --- | --- |
| encore 重启、GNOME 自动登录 | 通过；用户环境已有 `DISPLAY=:0`、`WAYLAND_DISPLAY=wayland-0` |
| encore → seraph SSH | 通过，linwhite 账户 |
| encore/seraph 系统构建及 switch | 通过，配置快照见第 9 节 |
| encore Home Manager | 已激活三个 `mc-*` 入口和 seraph DAP 标签 |
| seraph tailscale0 TCP 25565 | nft 运行规则已确认 |
| encore `:fabric:runClient --dry-run` | BUILD SUCCESSFUL |
| `mc-build-remote :fabric:runClient :fabric:runServer build --dry-run` | BUILD SUCCESSFUL |
| `mc-build-remote :fabric:classes :fabric:test` | 真实编译成功，Minecraft 工件准备成功；test 为 NO-SOURCE，不能称为测试用例通过 |
| Sunshine | 补齐 KMS 权限并唤醒屏幕后，H.264/HEVC VAAPI 编码器检测成功；47989/47990 监听 |
| 实际 MC 图形启动、联网进服、DAP attach、Moonlight 配对 | 尚未做交互验收，按下文完成 |

Gradle `--dry-run` 只跳过目标任务执行；首次仍会下载依赖、配置项目、编译 build-logic。
本次没有为验收长期运行游戏服务端，也没有改动 chorus 源码。
chorus 当前分支 `nixos-runtime-libs`，本地提交 `295d287`，工作区干净，未 push。

## 3. 每次开始开发

Mac 终端：

```sh
ssh chorus
```

此别名进入 encore 的持久 tmux 会话。不要写 `ssh chorus <命令>`，
它已有 RemoteCommand；执行单条远程命令请用 `ssh encore '<命令>'`。

encore 的 tmux 内：

```sh
cd ~/chorus
git status --short --branch
direnv allow                 # 首次或审核过 .envrc 变更后
java -version                # 此项目应使用 JDK 25
command -v jdtls
command -v mc-client mc-server-remote mc-build-remote
ssh seraph 'hostname; uptime; free -h'
```

如果 direnv 尚未加载，用下面的显式入口验证；不要用系统 Java 代替项目 JDK：

```sh
nix develop --no-pure-eval --command java -version
nix develop --no-pure-eval --command ./gradlew --version
```

建议 tmux 分三个窗口：编辑器、客户端、服务端日志。断开 SSH 后用 `ssh chorus` 返回。

## 4. 先 dry-run，再构建

在 encore `~/chorus`：

```sh
# 本机客户端任务图
nix develop --no-pure-eval --command ./gradlew --max-workers=4 :fabric:runClient --dry-run

# 同步到 seraph，检查客户端/服务端/全项目构建任务图
mc-build-remote :fabric:runClient :fabric:runServer build --dry-run

# 真实编译与测试入口（本次已执行）
mc-build-remote :fabric:classes :fabric:test

# 开发完成时的全项目构建（本次只验证了其任务图）
mc-build-remote build
```

远程构建产物留在 seraph 的 `~/chorus-build/<模块>/build/libs/`。
需要时从 encore 拉取：

```sh
mkdir -p ~/chorus-artifacts/fabric
rsync -av seraph:chorus-build/fabric/build/libs/ ~/chorus-artifacts/fabric/
```

不要把 worker 的整个 `build/` 复制回 encore：其中可能含绝对路径和本机缓存。
同一 worker 目录不要并发执行多次同步/构建。

## 5. Moonlight 与图形环境

**Sunshine 管理页面为 HTTPS 47990，47989 不是管理页面。**

在 Mac 新开终端建立管理隧道，并保持运行：

```sh
ssh -N -L 47990:127.0.0.1:47990 encore
```

1. 浏览器打开 `https://localhost:47990`；首次会有 Sunshine 自签名证书提示。
2. 首次设置 Sunshine 管理账户。
3. Mac Moonlight 手动添加 `encore`（或 `encore.inner.imdomestic.com`）。
4. Moonlight 显示 PIN，在 Sunshine Web UI 的 PIN 页面输入。
5. 选择 Desktop，确认能看见 encore 桌面并操作。

本次发现：GNOME 自动熄屏会导致 KMS monitor list 为空，Sunshine 转向 portal 后失败。
encore 的 Home Manager 已配置 GNOME `idle-delay=0`，避免自动熄屏；
这不保证合盖、手动关闭显示器或锁屏时的捕获行为。首次建议保持屏幕开启。

若此前已熄屏，在 encore 执行：

```sh
gdbus call --session --dest org.gnome.Mutter.DisplayConfig \
  --object-path /org/gnome/Mutter/DisplayConfig \
  --method org.freedesktop.DBus.Properties.Set \
  org.gnome.Mutter.DisplayConfig PowerSaveMode '<0>'
systemctl --user restart sunshine
journalctl --user -u sunshine -n 60 --no-pager
```

Sunshine 的 `active` 状态并不足以证明能串流；应确认编码器检测成功并完成 Moonlight 实测。

## 6. 第一次启动测试环境

### 服务端（seraph），入口在 encore

在 encore 的 `~/chorus`：

```sh
mc-server-remote
```

脚本会先停止旧服务端，再 rsync 到 `seraph:~/chorus-worker`，准备
`fabric/runs/server/eula.txt` 与 `server.properties`，启动远程 tmux 会话
`chorus-server`，然后跟随 `~/.cache/chorus-server.log`。
开发实例使用 `online-mode=false`，供开发客户端离线身份测试；仅通过 tailnet 开放端口。
首次可能需要下载和编译；等日志出现 `Done (...)!` 才算就绪，
脚本显示“已启动”仅表示 tmux 启动成功。

Ctrl-C 只退出日志跟随，服务端仍运行。检查/停止：

```sh
ssh seraph 'tmux ls; ss -ltn | grep 25565'
ssh seraph 'tail -n 80 ~/.cache/chorus-server.log'
mc-server-remote stop
```

正常停止会发送 `stop`，最多等待 20 秒再终止 tmux；重要存档请先手动等待保存完成。

### 客户端（encore）

另一个 encore tmux 窗口：

```sh
cd ~/chorus
mc-client
```

脚本借用 GNOME 用户环境，在 encore 桌面显示游戏，默认 NVIDIA PRIME offload。
在 Mac 的 Moonlight 里操作：多人游戏 → 服务器地址 **`seraph:25565`**。
不要填 `localhost`、Mac 地址或 WSL 的 `9950x`。

若需要对比核显：`MC_DGPU=0 mc-client`。
首次图形启动成功、加入服务端并验证 mod 行为后，才算端到端验收完成。

## 7. Neovim / Java 调试

在已进入项目 devenv 的 encore shell 中打开 Java 文件，例如先用
`git ls-files '*.java'` 选择实际文件，再 `nvim <文件>`。
项目有 `common/`、`fabric/`、`neoforge/`，不要假设根目录存在 `src/main/java`。
首次 JDTLS 会做 Gradle 导入和索引，需等待完成；可用 `:checkhealth vim.lsp` 排查。

源码导航准备在 encore 执行（远端生成的缓存不会自动成为本机 LSP 缓存）：

```sh
nix develop --no-pure-eval --command ./gradlew --max-workers=4 :fabric:genSources
```

`genSources` 是 Gradle 任务，不是 Neovim 的 `:fabric:genSources` 命令。

| 操作 | 快捷键 |
| --- | --- |
| 断点 | `<leader>db` |
| 启动/继续调试 | `<leader>dc` |
| 单步跳过 / 进入 | `<leader>do` / `<leader>di` |
| REPL | `<leader>dr` |
| DAP UI | `<leader>du` |
| 断开调试（不终止目标） | `<leader>dq` |

客户端调试：`mc-client --debug`，随后在 nvim `<leader>dc` 选
`Attach: encore 本机客户端`（127.0.0.1:5005）。

服务端调试：`mc-server-remote --debug`，脚本建立
encore 127.0.0.1:5006 → seraph 127.0.0.1:5005 隧道；在 nvim 选择
`Attach: seraph 服务端 (隧道 5006)`。等待 attach 时游戏暂停是正常的。
JDWP 无需开放到防火墙。若 5006 已占用，脚本会失败退出；先确认旧 SSH 隧道进程再结束它，
不要把任意占用 5006 的进程当成正确隧道。

Hot Code Replace 已启用，但不是任意代码变化都能热替换：
方法体调整可尝试，类结构、Mixin、注册项或资源变化通常需要重启游戏/服务端。

## 8. 日常维护与本地提交

```sh
# encore: ~/chorus
git status --short --branch
git switch -c feature/<你的功能名>   # 从含 NixOS 补丁的当前分支开始
# 编辑，保存
mc-build-remote :fabric:classes :fabric:test
# 需要实际游戏验证时，重启服务端并重新运行 mc-client
git diff --check
git diff
git add <明确的源码文件>
git commit -m "feat: 描述这次修改"
```

当前不执行 `git push`，不创建 PR。上游同步可先 `git fetch origin`、检查差异，
再决定合并方式；保留本地 `devenv.nix` 的 Linux runtime 库补丁。
不要直接把 worker 目录当 Git 仓库，也不要把缓存、世界存档或构建产物提交。

服务端世界位于 `seraph:~/chorus-worker/fabric/runs/server/`。
同步规则排除了 `runs/`，不会因正常 rsync 删除世界；备份前先停服：

```sh
mc-server-remote stop
mkdir -p ~/chorus-backups/server
rsync -av seraph:chorus-worker/fabric/runs/server/ ~/chorus-backups/server/
```

结束工作：退出游戏，`mc-server-remote stop`，保存并 commit，退出/分离 tmux。
不要把关闭日志窗口误认为停服。

## 9. Nix 配置维护与部署记录

源配置：
- `home/modules/chorus/default.nix`：三个入口、encore GNOME 自动熄屏设置。
- `home/modules/nixvim/linwhite/default.nix`：Java/DAP 配置。
- `nixos/hosts/encore/system.nix`：Sunshine、KMS 权限、自动登录。
- `nixos/hosts/seraph/system.nix`：tailnet MC 防火墙。

本轮配置提交 `d0c30ea` 只保存在 Mac 的 nix-config；部署通过归档传输到
两机 `~/chorus-config-d0c30ea`，使用该快照里的 `just switch` 和 `just hm`。
后续 GNOME 自动熄屏修复随文档作独立本地提交，并同步到 encore 的部署快照。
**远端原来的 `~/.config/nix-config` 不一定包含本轮提交，不能直接从旧 checkout 重建。**
GitHub 上也没有这些本地提交；未来从远端 main 部署前要先传递并合入本地修改，避免回退。

后续在持有完整修改、已核对新鲜度的配置目录内执行：

```sh
# encore：系统和 home 是两个独立操作
just switch encore
just hm encore linwhite

# seraph：仅系统防火墙修改需要这个
just switch seraph
```

Mac 不直接执行 Linux 的 `just hm encore linwhite`；应 SSH 到 encore 后运行。
仅修改 chorus Java 源码不需要 NixOS/Home Manager rebuild。
避免在 Mac 上全编队部署；本次仅部署 encore 与 seraph。

## 10. 快速排障

| 现象 | 检查 |
| --- | --- |
| 找不到 mc 命令 | encore 上检查 `command -v`，确认 Home Manager 已激活、重开 shell |
| 客户端无图形会话 | `systemctl --user show-environment` 是否有 DISPLAY/WAYLAND_DISPLAY |
| Sunshine active 但黑屏/无 Web UI | 检查日志、屏幕 PowerSaveMode，唤醒并重启 Sunshine |
| 无法连 seraph | encore 上 `ssh seraph hostname`，核对其当前启动的是原生 NixOS |
| 服务端启动后马上退出 | 读 `~/.cache/chorus-server.log`，不要只看 tmux 启动提示 |
| 构建 OOM | 停并行任务；降低 `--max-workers`，结合 `free -h` 调整项目 JVM 参数 |
| JDTLS 不工作 | 从 devenv 内启动 nvim，核对 JDK 25、jdtls PATH、Gradle 导入日志 |
| 测试显示 NO-SOURCE | 表示没有测试源码，不是已有测试通过 |

实际运行产生的新错误应连同主机、分支/提交、命令、日志记录，区分
“环境/任务图通过”“真实编译通过”“游戏与调试交互通过”。
