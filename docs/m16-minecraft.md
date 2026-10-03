# m16 Minecraft 服务

m16 运行 tank 的 Minecraft 数据副本。公网入口的变更需要获得用户确认。

## 连接地址

Java 客户端通过 `m16.inner.imdomestic.com:25565` 连接；同一局域网可以使用
`10.1.2.137:25565`。Bedrock 使用相同主机的 UDP `19132` 端口。
Tailscale 地址为 `100.64.0.43`。
Bedrock 协议响应版本为 `1.21.130`。

| 服务 | 版本 | 本机端口 | 最大 Java 堆内存 |
| --- | --- | --- | --- |
| proxy | Velocity 3.5.0，构建 600 | TCP 25565 | 512 MiB |
| bedrock-proxy | Velocity、Geyser 2.9.2，构建 1015 | TCP 25572、UDP 19132 | 512 MiB |
| lobby | Paper 1.21.1，构建 133 | TCP 25568 | 2 GiB |
| bingo | Fabric 1.21.11 | TCP 25573 | 4 GiB |
| speedrun | Paper 1.21.11，构建 132 | TCP 25567 | 4 GiB |
| GTL | Forge 1.20.1-47.3.7 | TCP 25560 | 6 GiB |

代理默认进入 lobby；代理注册的子服名称为 `lobby`、`bingo`、`speedrun`、`gtl`。
子服、RCON 和数据库只监听本机地址。Wi-Fi 和 Tailscale 接口开放 Java 与
Bedrock 的客户端端口。

## 数据与账户

完整数据位于 `/var/lib/minecraft`，包括历史世界备份、玩家数据、管理员名单与
封禁名单。服务使用独立的 `minecraft` 账户；hank 和 linwhite 属于 minecraft
用户组。

PostgreSQL 16 保存 `minecraft`、`luckperms` 数据库，MariaDB 保存 `minecraft`
数据库。子服 LuckPerms 和 CMI 使用 m16 的数据库；代理 LuckPerms 保留原有
H2 数据库，SkinsRestorer 保留原有文件存储。
Bukkit 与 Velocity 的 LuckPerms 使用官方固定版本 5.5.71。

凭据位于 `/var/lib/minecraft-secrets`：`runtime.env` 提供插件启动环境，
`database.json` 通过 systemd credentials 提供数据库初始化凭据，
`forwarding.secret` 提供代理转发认证。凭据需要单独备份，不进入 Git。

首次迁移备份位于 tank 的 `/root/.work/m16-minecraft-export`、Mac 仓库的
`.work/m16-minecraft/source-export` 和 m16 的 `/root/.work/m16-minecraft`。
`SHA256SUMS` 覆盖完整存档及三个数据库导出文件。

## 服务管理

各实例由 `minecraft-server-<名称>.service` 管理，随系统启动，并在运行失败时
自动重新启动。数据库凭据服务先于 Minecraft 启动。完成数据恢复后，
`/var/lib/minecraft/.restored` 标记允许服务启动。

```sh
sudo systemctl status minecraft-server-proxy.service
sudo journalctl -u minecraft-server-GTL.service -f
sudo systemctl restart minecraft-server-speedrun.service
```

所有 Minecraft 进程位于 `minecraft.slice`，内存高水位为 18 GiB，上限为
20 GiB。各实例的缓存目录位于 `/var/cache/minecraft/<名称>`。

## 持续运行

m16 配置忽略合盖与空闲事件，禁用 systemd 的睡眠、挂起、休眠和混合睡眠
入口，禁用 GDM 自动挂起，并锁定两个用户的 GNOME 空闲睡眠设置为 `nothing`。
NetworkManager 禁用 Wi-Fi 节能，保存的网络配置自动连接；SSH、Tailscale 和
NetworkManager 随系统启动。

## 部署验证

2026-10-04 已验证完整备份的 SHA-256、四个世界的名称与种子、管理员名单和
封禁名单。Java 代理、Bedrock 代理及四个子服均通过 Minecraft 协议查询。

保留维护 U 盘插入的状态下，m16 已完成重启并从 SSD 启动 NixOS。六个服务、
PostgreSQL 和 MariaDB 自动恢复，局域网与 Tailscale SSH 均可连接，systemd
没有失败单元。重启后再次验证了休眠入口、GNOME 设置锁定及 Wi-Fi 节能设置。

## 割接条件

用户确认副本后，重新核对 tank 是否产生新的世界或数据库数据，并在一致的
停止状态完成最终同步。随后更新公网入口到 m16，验证客户端登录、子服切换和
权限数据。

`nixos/modules/minecraft/gate.nix` 的 Gate 配置使用 PROXY protocol。连接该入口时，
需要同时配置 m16 主代理接收 PROXY protocol。当前副本接受客户端直接连接。
