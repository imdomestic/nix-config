# linwhite 的 Tailscale 文件共享

seraph 与 encore 使用 `nixos/modules/linwhite-smb.nix` 提供 `/home/linwhite`
的可读写 SMB 共享。aegis 通过 Tailscale 使用 linwhite 账户连接，挂载由
`darwin/modules/linwhite-smb.nix` 中的 `launchd.user.agents` 管理。

| 服务器 | aegis 挂载目录 | 家目录快捷入口 | Finder 地址 |
| --- | --- | --- | --- |
| seraph | `/Volumes/seraph-linwhite` | `~/Servers/seraph` | `smb://linwhite@seraph/seraph-linwhite` |
| encore | `/Volumes/encore-linwhite` | `~/Servers/encore` | `smb://linwhite@encore/encore-linwhite` |

aegis 的连接地址和钥匙串条目使用短名称 `seraph`、`encore`。Tailscale 的
DNS 搜索域将这两个名称解析为对应服务器的 Tailscale 地址。

Samba 只绑定服务器自己的 Tailscale IPv4 地址与 TCP 445 端口。Samba 的
访问白名单和 nftables 规则均只允许 aegis 的 `100.64.0.25`；该地址已经通过
Tailscale 节点状态核实。Tailscale 提供设备认证与传输加密，SMB 验证 linwhite
账户的专用密码。

每台服务器的 `linwhite-smb-password.service` 首次启动时生成专用密码，保存为
root 所有的 `/var/lib/linwhite-smb/password`，目录权限 `0700`，文件权限
`0600`，并配置 Samba 账户。aegis 的对应凭据保存于 linwhite 的登录钥匙串，
密码通过 SSH 传输，配置仓库和 Nix store 中只保存连接参数。

`org.nixos.linwhite-smb-seraph` 与 `org.nixos.linwhite-smb-encore` 在 linwhite
登录时启动，并每隔 60 秒检查挂载。`scripts/mount-linwhite-smb.py` 使用
PyObjC 的 Security 与 NetFS 模块读取钥匙串并调用 macOS 原生挂载接口。
卷挂载到 `/Volumes/`，脚本核实服务器、共享名称和连接账户，并创建家目录快捷入口。
已经挂载的目录直接保持现状；连接失败时进程立即终止并记录错误，launchd 的
下一次定时执行重新尝试连接。

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
如果 aegis 的 Tailscale 节点身份更换导致 IPv4 地址变化，需要同步更新白名单及
nftables 规则。

aegis 的挂载配置通过 `just darwin aegis` 激活。用户 LaunchAgent 生成文件
位于对应系统构建结果的 `user/Library/LaunchAgents/`，可以由 linwhite 使用
`launchctl bootstrap gui/501 <plist>` 加载。

本次部署由 linwhite 直接加载两个 Nix 生成的用户 LaunchAgent，
`~/Library/LaunchAgents/org.nixos.linwhite-smb-*.plist` 指向构建结果，
`~/.local/state/nix/gcroots/linwhite-smb` 保留其闭包。aegis 的完整系统激活需要
本机 sudo 认证，`/run/current-system` 仍指向原有系统代际。

## 验证（2026-10-06）

全部 20 个 NixOS 配置与 4 个 nix-darwin 配置求值通过，aegis 的系统闭包构建
通过。seraph 与 encore 的系统部署均已确认，Samba 和密码配置服务处于 active
状态，两台服务器均没有失败的系统服务。

aegis 已使用 linwhite 账户建立 SMB 3.1.1 连接。两个共享均完成 1 MiB 文件读写、
中文文件名、扩展属性、重命名、SHA-256 校验与删除验证；远端文件所有者为
linwhite，文件权限为 `0600`，目录权限为 `0700`。卸载两个共享后，用户任务
均在定时执行时自动重新挂载，退出状态为 `0`，随后再次通过文件操作验证。
实际挂载来源为 `//linwhite@seraph/seraph-linwhite` 和
`//linwhite@encore/encore-linwhite`；短名称配置的两个用户任务退出状态均为 `0`，
并通过上述文件操作验证。

两个服务只监听各自 Tailscale IPv4 地址的 TCP 445。seraph 与 encore 之间的
SMB 连接均超时，nftables 拒绝规则的计数增加，验证了 aegis 地址限制。
