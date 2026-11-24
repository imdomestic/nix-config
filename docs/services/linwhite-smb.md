# seraph / encore Tailscale SMB 服务

seraph 与 encore 使用 `system/modules/linwhite-smb/nixos.nix` 提供 `/home/linwhite`
的可读写 SMB 共享，服务仅通过 Tailscale 网络开放。

| 服务器 | 共享名称 | 导出目录 |
| --- | --- | --- |
| seraph | `seraph-linwhite` | `/home/linwhite` |
| encore | `encore-linwhite` | `/home/linwhite` |

Samba 只绑定服务器自己的 Tailscale IPv4 地址与 TCP 445 端口。Samba 的
访问白名单和 nftables 规则均允许 aegis 的 `100.64.0.25`；encore 还允许
Android 设备 ruin 的 `100.64.0.20`，seraph 不允许 ruin。这些地址已经通过
Tailscale 节点状态核实。Tailscale 提供设备认证与传输加密，SMB 再验证账户密码；
白名单是按设备而不是按 SMB 用户绑定的。

每台服务器的 `linwhite-smb-password.service` 首次启动时生成 linwhite 的专用密码，
保存为 root 所有的 `/var/lib/linwhite-smb/password`。encore 的
`ruin-smb-password.service` 为独立的 `ruin` SMB 账户生成密码，保存于
`/var/lib/linwhite-smb/ruin-password`。目录权限 `0700`，密码文件权限 `0600`；
密码不写入配置仓库或 Nix store。`ruin` 是无登录 shell、无家目录的系统账户，
SMB 文件操作仍以 linwhite 身份执行，因此它可以读写 linwhite 的整个家目录。

首次部署 encore 后，在 encore 本机运行 `sudo cat /var/lib/linwhite-smb/ruin-password`
取得密码。在 ruin 的 SMB 客户端连接 `smb://encore.inner.imdomestic.com/encore-linwhite`，
使用用户名 `ruin` 和该密码；设备须连接 Tailscale。

文件操作使用各服务器的 linwhite 账户，新建文件权限为 `0600`，新建目录权限为
`0700`。`catia`、`fruit`、`streams_xattr` 提供 macOS 文件名、Finder 元数据和
扩展属性支持。家目录中的隐藏文件同样可以访问。

共享属于系统配置。后续部署使用 `just deploy-system seraph` 与
`just deploy-system encore`。从 macOS 发起时，使用下列命令：

```sh
deploy .#seraph.system --remote-build --temp-path /home/linwhite/.config/nix-config/.work/linwhite-smb-deploy -- --option max-jobs 2 --option cores 4
deploy .#encore.system --remote-build --temp-path /home/linwhite/.config/nix-config/.work/linwhite-smb-deploy -- --option max-jobs 2 --option cores 4
```

部署前确认目标机器的临时目录存在。`my.tailscale.bindServices` 在 Samba 启动前
确认 Tailscale 地址就绪；`my.tailscale.guardedTCPServices` 限制 SMB 的接入接口。
如果 aegis 或 ruin 的 Tailscale 节点身份更换导致 IPv4 地址变化，需要更新对应
白名单；Samba 和 nftables 从同一列表生成。

## aegis 自动挂载与固定路径

客户端配置为 `system/modules/linwhite-smb/darwin.nix`，属于 **aegis 系统闭包**，
不是 Home Manager。用户 LaunchAgent 每 60 秒检查一次：

| 共享 | 固定挂载点 | 固定快捷入口 |
| --- | --- | --- |
| encore | `/Volumes/encore-linwhite` | `~/Servers/encore` |
| seraph | `/Volumes/seraph-linwhite` | `~/Servers/seraph` |

系统激活只创建缺失的挂载目录，交给 linwhite 所有；不会改动已存在/已挂载目录。
脚本通过钥匙串取凭据、禁止认证弹窗，用 NetFS 指定原挂载点；不使用自动选名，
也不把快捷入口自动改指向 `-1`。已登记的同一共享无论在什么路径都先识别，
避免重复挂载；短时断网、旧会话重连期间保留原入口，不强制卸载。

- 网络未恢复：检查 DNS/TCP 445；未就绪就等待下一轮。
- 挂载仍登记但目录不可访问：`waiting-session`，等待 macOS 自身重连。
  **不会自动修复永久卡住的旧挂载**，以免破坏打开的文件。
- 挂载已消失：先留 60 秒给系统重连，再检查两次网络可达性并重挂原路径。
- 原路径被非空本地目录、其他卷或符号链接占用：报错，保留现状；不删除文件。
- 同一共享已挂在 `-1` 等其他路径：报错，要求关闭文件后人工迁回；不制造第二个挂载。

日志：`~/Library/Logs/linwhite-smb-{encore,seraph}.log`，仅状态变化时输出时间戳。
最近检查时间和状态在 `~/Library/Application Support/linwhite-smb/<host>.json`。
该目录的 lock 文件用于每共享互斥；不要删除仍在运行进程持有的 lock 文件。

### 首次切换新版与现有后缀卷的迁移

2026-11-03 提交时仅完成代码和离线验证，**未激活，seraph 仍挂在 `-1`**。
首次上线需另行安排操作窗口：

1. 关闭共享上的文件、终端工作目录及使用它们的程序；确认没有待保存数据。
2. 暂停 seraph 的旧代理，避免迁移过程中它继续使用自动选名逻辑：
   `launchctl bootout gui/$(id -u)/org.nixos.linwhite-smb-seraph`。
3. 从 Finder 正常推出 seraph 的现有卷。若提示正在使用或推出失败，先排查占用，
   **不使用强制卸载**，也不删除 `/Volumes` 下的目录。
4. 按 `AGENTS.md` 做 freshness check 后，用 `just darwin aegis` 激活客户端系统配置。
   确认两个 LaunchAgent 已加载；若未加载，先用对应 plist 执行 `launchctl bootstrap`，
   不同时启动旧脚本。服务器配置无需改动，也不需要 home 激活。
5. 观察日志及 `mount`：最多等待两个正常检查周期，再确认固定路径、目录读取与
   `~/Servers/` 入口；使用临时文件完成写入、读取、删除验证。
6. 经用户确认后测试短时断网和睡眠唤醒；验收没有新后缀卷、原路径恢复、日志能
   区分网络未就绪与旧会话未恢复。若旧挂载永久卡住，先关闭文件再正常推出。

仅检查逻辑、不接触挂载或钥匙串的回归测试：

```sh
python3 scripts/test-mount-linwhite-smb.py
nix eval --raw .#darwinConfigurations.aegis.config.system.build.toplevel.drvPath
```

根因、时间线与验证边界：`docs/incidents.md#smb-fixed-mountpoint`。
