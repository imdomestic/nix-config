# seraph / encore Tailscale SMB 服务

seraph 与 encore 使用 `system/modules/linwhite-smb/nixos.nix` 提供 `/home/linwhite`
的可读写 SMB 共享，服务仅通过 Tailscale 网络开放。

| 服务器 | 共享名称 | 导出目录 |
| --- | --- | --- |
| seraph | `seraph-linwhite` | `/home/linwhite` |
| encore | `encore-linwhite` | `/home/linwhite` |

Samba 只绑定服务器自己的 Tailscale IPv4 地址与 TCP 445 端口。Samba 的
访问白名单和 nftables 规则均只允许 aegis 的 `100.64.0.25`；该地址已经通过
Tailscale 节点状态核实。Tailscale 提供设备认证与传输加密，SMB 验证 linwhite
账户的专用密码。

每台服务器的 `linwhite-smb-password.service` 首次启动时生成专用密码，保存为
root 所有的 `/var/lib/linwhite-smb/password`，目录权限 `0700`，文件权限
`0600`，并配置 Samba 账户。密码不写入配置仓库或 Nix store。

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

## 验证（2026-10-06）

全部 20 个 NixOS 配置与 4 个 nix-darwin 配置求值通过。
seraph 与 encore 的系统部署均已确认，Samba 和密码配置服务处于 active
状态，两台服务器均没有失败的系统服务。

获准客户端已建立 SMB 3.1.1 连接。两个共享均完成 1 MiB 文件读写、
中文文件名、扩展属性、重命名、SHA-256 校验与删除验证；远端文件所有者为
linwhite，文件权限为 `0600`，目录权限为 `0700`。

两个服务只监听各自 Tailscale IPv4 地址的 TCP 445。seraph 与 encore 之间的
SMB 连接均超时，nftables 拒绝规则的计数增加，验证了 aegis 地址限制。
