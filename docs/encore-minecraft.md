# encore Minecraft 服务

encore 承载 Minecraft 服务，tokyo 的 Gate 通过 Tailscale 将玩家连接转发到 encore。

## 连接地址

Java 客户端继续使用 tokyo 的原有地址，公网 IPv4 入口为 `43.130.229.141:25565`。
Gate 的全部主机名路由指向 `encore.inner.imdomestic.com:25565`，并使用 PROXY
protocol 传递玩家真实地址。encore 的 Java 入口由 Gate 转发连接。

Bedrock 使用 `encore.inner.imdomestic.com:19132`，局域网地址为 `10.1.2.137:19132`。
encore 的 Tailscale 地址为 `100.64.0.43`。
Bedrock 协议响应版本为 `26.51`。

| 服务 | 版本 | 本机端口 | 最大 Java 堆内存 |
| --- | --- | --- | --- |
| proxy | Velocity 4.2.0，构建 30 | TCP 25565 | 512 MiB |
| bedrock-proxy | Velocity、Geyser 2.11.3，构建 1247 | TCP 25572、UDP 19132 | 512 MiB |
| lobby | Paper 1.21.1，构建 133 | TCP 25568 | 2 GiB |
| bingo | Fabric 1.21.11 | TCP 25573 | 4 GiB |
| speedrun | Paper 1.21.11，构建 132 | TCP 25567 | 4 GiB |
| GTL | Forge 1.20.1-47.3.7 | TCP 25560 | 6 GiB |

代理默认进入 lobby；代理注册的子服名称为 `lobby`、`bingo`、`speedrun`、`gtl`。
子服、RCON 和数据库只监听本机地址。Java 代理接收 Gate 的 PROXY protocol
连接，Bedrock 代理接收客户端 UDP 连接。

两个代理使用 Java 25，代理与插件均固定下载地址和 SHA-256：

| 插件 | 版本 |
| --- | --- |
| ViaVersion / ViaBackwards | 5.12.0 |
| ViaRewind | 4.2.0 |
| TAB | 6.2.0 |
| VelocityScoreboardAPI | 2.1.1 |
| TAB-Bridge（lobby、speedrun） | 6.2.3 |
| SkinsRestorer（代理、lobby、speedrun） | 15.12.6 |
| Velocircon | 1.0.7 |
| CMIV | 1.0.2.4 |

ViaVersion 5.12.0 支持 Java 26.3 客户端。VelocityScoreboardAPI 2.1.1 要求
Java 25 和 Velocity 4.2.0 构建 30；TAB 配置使用版本 7。
LuckPerms Velocity 5.5.71 与 Ambassador 1.4.5 已核对为上游最新发布版本。

## 数据与账户

完整数据位于 `/var/lib/minecraft`，包括历史世界备份、玩家数据、管理员名单与
封禁名单。服务使用独立的 `minecraft` 账户；hank 和 linwhite 属于 minecraft
用户组。

PostgreSQL 16 保存 `minecraft`、`luckperms` 数据库，MariaDB 保存 `minecraft`
数据库。子服 LuckPerms 和 CMI 使用 encore 的数据库；代理 LuckPerms 保留原有
H2 数据库，SkinsRestorer 保留原有文件存储。
Bukkit 与 Velocity 的 LuckPerms 使用官方固定版本 5.5.71。

凭据位于 `/var/lib/minecraft-secrets`：`runtime.env` 提供插件启动环境，
`database.json` 通过 systemd credentials 提供数据库初始化凭据，
`forwarding.secret` 提供代理转发认证。凭据需要单独备份，不进入 Git。

首次迁移备份位于 tank 的 `/root/.work/encore-minecraft-export`、Mac 仓库的
`.work/encore-minecraft/source-export` 和 encore 的 `/root/.work/encore-minecraft`。
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

encore 配置忽略合盖与空闲事件，禁用 systemd 的睡眠、挂起、休眠和混合睡眠
入口，禁用 GDM 自动挂起，并锁定两个用户的 GNOME 空闲睡眠设置为 `nothing`。
NetworkManager 禁用 Wi-Fi 节能，保存的网络配置自动连接；SSH、Tailscale 和
NetworkManager 随系统启动。

## 部署验证

2026-10-04 已验证完整备份的 SHA-256、四个世界的名称与种子、管理员名单和
封禁名单。Java 代理、Bedrock 代理及四个子服均通过 Minecraft 协议查询。

1.21.5 协议客户端已通过公网入口进入 lobby，再执行 `/server bingo`，收到
出生位置与计分板并持续连接。收到的 24 个 bingo 计分板文本全部通过
Minecraft 1.21.5 官方 `ComponentSerialization.CODEC` 与 `NbtOps` 解码检查。

26.3 协议客户端（协议编号 777）已通过公网完成 `lobby → bingo → speedrun → lobby`
登录与切换，收到各子服出生位置和计分板，在每次切换后保持连接 10 秒。
测试使用 MCProtocolLib 26.3，所有接收数据包均正常解码。Bedrock UDP 状态查询
返回版本 26.51，Geyser 与两个代理、四个子服均正常启动。

保留维护 U 盘插入的状态下，encore 已完成重启并从 SSD 启动 NixOS。六个服务、
PostgreSQL 和 MariaDB 自动恢复，局域网与 Tailscale SSH 均可连接，systemd
没有失败单元。重启后再次验证了休眠入口、GNOME 设置锁定及 Wi-Fi 节能设置。

## 公网入口维护

Gate 由 tokyo 的 `podman-gate.service` 管理，并启用开机启动。
`nixos/modules/minecraft/gate.nix` 声明后端域名、PROXY protocol 和 TCP `25565`
防火墙端口；`nixos/hosts/encore/minecraft.nix` 声明代理接收 PROXY protocol。

2026-10-04 已从公网查询服务状态，并通过实际协议客户端登录 encore 大厅、
确认出生位置。encore 的代理和大厅日志确认了同一条登录连接及玩家真实公网地址。
tokyo 与 encore 的系统配置均已激活，Gate 后端通过 Tailscale 域名解析到 encore。

encore 重启后已验证六个 Java 状态查询、Bedrock UDP 状态查询，并使用
26.3 协议客户端从公网完成 `lobby → bingo → speedrun → lobby` 登录与切换。
Windows 的管理名称为 `m16.inner.imdomestic.com`。
