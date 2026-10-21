# M1 Pro 到 M3 Max 的 Mac 迁移

2026-10-22：旧 M1 Pro 改为 `m1elite`，新 M3 Max（36 GB / 1 TB）使用
`praxic`。Apple 迁移助理通过雷电连接迁移完整 `hank` 账户与普通应用；新机已有
`hank` 和相同 Apple ID，用户明确允许替换，新账户无须保留。用户明确取消额外备份，
保留旧机原数据作为迁移验收前的回退。OrbStack 数据不迁移。

## 执行状态

- 仓库同步至 `00c8eff`；原有 `flake.lock` 暂存和未暂存改动均保留。
- 已停止旧机 OrbStack 服务；数据已移动到 `/Users/Shared/mac-migration-excluded-hank/data`，
  同一文件系统内移动，没有额外复制。迁移时必须排除该 Shared 目录。
- 已拆出两台 Mac 共用的 Darwin 模块并注册 `m1elite`；旧机系统求值通过，UID 501、
  无 WireGuard 接口，激活待完成。
- 雷电桥连接活动；已通过 SSH 核对新机 `192.168.2.112`：M3 Max、36 GB、
  macOS 27.0.1（与旧机相同），`hank` 当前 UID 为 502，尚无 `/nix`。
  新机配置已设 UID 502，迁移后激活前仍须复查。
- Apple 迁移、独立 `/nix` 卷及两台机器的激活待完成。

## App 数据

完整迁移 `/Users/hank`，包括隐藏目录、Library、Containers、Group Containers 和
钥匙串。Apple ID 同步不能代替 App 本地数据库迁移。传输前正常退出 App，停止
PostgreSQL。迁移助理会退出当前会话，后续工作从本文件接续。

| App | 已发现的数据位置与验收重点 |
| --- | --- |
| Codex | `~/.codex` 整体；会话与 `state_5.sqlite`、`thread_history_1.sqlite` 一起迁移，核对历史、配置、skills、memories |
| ChatGPT 桌面端 | 本机 `ChatGPT.app` 标识为 `com.openai.codex`；保留 `~/Library/Application Support/` 下的 `Codex`、`OpenAI`、`com.openai.codex` 及相关偏好设置、Group Container、钥匙串 |
| Claude 桌面端 | `~/Library/Application Support/Claude`、`Claude-3p`；包含 `local-agent-mode-sessions`、`claude-code-sessions`、`claude-code-vm` 等本地状态；`~/.claude` 另随账户迁移 |
| QQ | `~/Library/Containers/com.tencent.qq` 及相关容器，核对历史消息与附件 |
| 微信 | `~/Library/Containers/com.tencent.xinWeChat`、`~/Library/Group Containers/5A4RE8SF68.com.tencent.xinWeChat` 等关联容器，核对历史消息与附件 |
| 浏览器 | 完整个人资料与钥匙串一起迁移，核对书签、扩展、标签页和重要网站登录 |

QQ、微信部分 Group Container 受 macOS 隐私保护，当前命令行不能完整读取；由 Apple
迁移助理迁移，不能以当前只读盘点代替迁后验收。Claude 的
`vm_bundles/claudevm.bundle/rootfs.img` 逻辑大小 10 GiB、实际占用约 8.1 GiB，
也属于该 App 的本地数据。

OrbStack 原来的 `~/Library/Group Containers/HUAQ24HBR6.dev.orbstack/data` 已移动到
`/Users/Shared/mac-migration-excluded-hank/data`。其中 `data.img.raw` 逻辑大小约
926.35 GiB、实际占用约 9.33 GiB；迁移时排除整个 `mac-migration-excluded-hank`
目录，不要重新打开 OrbStack。旧数据可在原机移回原路径恢复。
官方说明：https://docs.orbstack.dev/faq

## Apple 迁移步骤

1. 两台接电、雷电直连；核对新机系统版本，必要时更新新机。
2. 新机打开迁移助理，选择从另一台 Mac；旧机选择迁移到另一台 Mac。
3. 核对安全码和雷电传输方式。选择应用程序和完整 `hank`；不选“其他文件和文件夹”，
   以排除 Shared 内暂存的 OrbStack 数据。系统和网络设置交由 Nix 重新配置，
   旧 `/nix` 独立卷也不参与迁移。
4. 同名账户选择用旧机 `hank` 替换新机 `hank`。用户已确认新账户没有需保留的数据。
5. 迁移后登录 `hank`，按系统提示重新验证 Apple ID / 钥匙串；暂不启动 VPN。

官方步骤：https://support.apple.com/en-au/102613

## Nix 恢复 {#nix-restore}

新机使用独立、大小写敏感、加密的 APFS `Nix Store` 卷，挂载 `/nix`，与系统卷共享
APFS 容器空闲空间，不设置固定分区容量。由 Determinate Nix Installer 创建和管理卷，
核对当前安装器的 `install macos --case-sensitive --encrypt true` 选项后安装。

安装前检查是否迁入旧 `/etc/fstab` UUID、`/etc/synthetic.conf`、launchd 配置或残留
Nix 安装状态；不要盲目重复创建卷。安装后检查加密和大小写敏感性，并重启确认自动挂载。
保留 `use-case-hack = false`。

旧机 `hank` 为 UID 501，登录 shell 为 `/run/current-system/sw/bin/zsh`；新机恢复
Nix 前此路径可能不存在，可用系统 `/bin/zsh` 或临时管理员引导。实测新机
`id -u hank` 后更新 `nixos/hosts/praxic/default.nix`，不要直接更改账户 UID。

每次激活前 fetch 并检查配置漂移。分别验证、激活系统与 standalone Home Manager：

```sh
# 旧 M1 Pro
sudo just darwin m1elite
just hm m1elite hank

# 新 M3 Max，先确认 UID 与 /nix 状态
sudo just darwin praxic
just hm praxic hank
```

旧机清空或 GC 之前保留必要的系统 / home 闭包，必要时使用 `nix copy` 传到新机，
不复制整套 `/nix` 数据库和所有历史 generation。

## 网络身份 {#network-identity}

旧机当前 Tailscale 节点 ID 为 1，DNS 为 `praxic.inner.imdomestic.com`、IPv4 为
`100.64.0.1`。先将旧机的本地和 Headscale 名称改为 `m1elite`，再把新机以独立
设备身份注册为 `praxic`；不要让两台同时使用迁移复制来的 Tailscale 设备状态。

WireGuard 的 `10.0.0.65/24` 留给新 `praxic`，`m1elite` 不配置该接口。当前
`/Users/hank/Documents/privatekey` 与 `presharedkey` 未找到，所以新机暂不自动启动
wg0。确认密钥、服务端 peer 以及旧机隧道已停后再启用；旧机如仍需 WireGuard，另配
独立密钥和地址。SSH / GPG / age 是个人密钥，随用户迁移并核对指纹与权限。

## 迁后验收

- 旧机与新机分别报告 `m1elite`、`praxic`，Nix 系统和 home 均正确激活。
- `/nix` 独立卷在重启后自动挂载，Nix daemon 与普通终端正常。
- Codex 历史可见、任务可打开；ChatGPT 和 Claude 的云端及本地内容逐项检查。
- QQ、微信核对较早与最近的消息、图片、文件；浏览器检查资料、扩展和重要登录。
- 项目包含未提交文件；SSH、Git 签名、SOPS 解密成功，敏感内容不输出到日志。
- PostgreSQL 17 可连接，旧机的 `hank` 与 `postgres` 数据库正常。
- Tailscale 两台为独立设备；Touch ID、Apple Pay、网络扩展重新授权，验证 FileVault 解锁。
- 已激活的配置使用明确提交保存并推送；原有无关 `flake.lock` 改动不混入迁移提交。
