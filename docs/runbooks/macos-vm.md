# tank 上的 macOS 虚拟机（maxx 的 iMessage）

maxx 的 iMessage 桥（Messages.app + `imsg` + max 仓库的 `bridge/imsg`）跑在 tank 上的一台
macOS 虚拟机里。为什么这么做见 [macos-vm](../decisions.md#macos-vm)，配置在
`hosts/tank/macos-vm/`。

## 布局

- `macos-vm.service`，以 `macos-vm` 用户跑 QEMU/KVM + OpenCore（取自 OSX-KVM
  `4c378a4`，那次提交加了 Tahoe）。4 vCPU、8 GiB。
- 网络：tap `macos0`，tank 是 `10.234.0.1`，客体由 networkd 的 DHCP 发 `10.234.0.2`。
  客体只能出公网：LAN、tailnet、tank 自己开着的端口一律进不去（nft 表 `inet macos-vm`）。
  tank 可以主动连客体（maxx 连桥、ssh 管理）。
- 状态在 `/data/services/macos-vm`：
  - `mac_hdd.img`：80G 系统盘，稀疏的 raw 文件（客体里的 APFS 自己就是写时复制，不再叠一层
    qcow2）。**别给它设 bcachefs nocow**，设过一次，安装数据坏了，见
    [macos-vm-nocow](../incidents.md#macos-vm-nocow)；
  - `OVMF_VARS.fd`：NVRAM；
  - `stop_key`、`known_hosts`：停机用的 ssh 密钥；
  - `BaseSystem.img`：只在安装时放，存在就挂上。
  首次启动时没有的会自动建，已有的不会覆盖。
- 身份（SMBIOS）在 sops：`secrets/hosts/tank.yaml` 的 `macos-vm/{serial,mlb,rom,uuid}`，
  机型固定 iMac19,1（不带 T2，见下）。每次启动渲染进 `/run/macos-vm/opencore.img`，不进 store。
  en0 的 MAC 就是 `rom`。
- VNC 只听 `127.0.0.1:5947`，密码是 `macos-vm/vnc-password`。
- OpenCore 不显示启动菜单，直接引导 macOS 设的默认盘（OpenCanopy 的倒计时在这台上不走，
  无人值守的重启会卡在菜单）。要菜单：VNC 连着，开机时按住 Option。
- 停机：先 ssh 进客体执行 `shutdown -h now`（客体只允许这把钥匙做这一件事），不通就按
  ACPI 电源键，120 秒后 systemd 直接杀 QEMU。

## 身份：生成一次，激活之后别再改

serial 和 MLB 用 OpenCorePkg 的 `macserial` 生成：

```sh
macserial -m iMac19,1 -n 10    # 每行：serial | MLB，两个成对用
```

拿 serial 去 <https://checkcoverage.apple.com> 查，要的是**查不到**（不是任何真机的）。
macserial 生成的号格式和真机一样，常常撞上真机：2026-11-09 第一次生成的那个查出来是
一台 2021 年买的 iMac，所以一次多生成几个，挑第一个查不到的。写进 sops：

```sh
sops set secrets/hosts/tank.yaml '["macos-vm"]["serial"]' '"<serial>"'
sops set secrets/hosts/tank.yaml '["macos-vm"]["mlb"]' '"<MLB>"'
```

`rom`（Apple OUI 开头的 6 字节，比如 `3c0754` 加 `openssl rand -hex 3`）和 `uuid`（`uuidgen`）
跟着一起换，`vnc-password` 不用动。

机型要不带 T2 的。最早用的 iMac20,1 带 T2，注册 iMessage 时 macOS 要给 Apple 做 T2 的硬件证明，
客体做不出来，注册被拒（6001，见 [macos-vm-apple-id](../incidents.md#macos-vm-apple-id)）。
Sequoia 支持的 iMac 里只有 iMac19,1 不带 T2；代价是升不了 Tahoe。

换身份时（只在 iMessage 还没激活过时）一并清掉旧的痕迹：客体里退出 Messages，删
`~/Library/{Messages,IdentityServices}` 和 `~/Library/Preferences/com.apple.{iChat,imagent,imessage.bag,madrid,imservice.ids.*}.plist`；
停机后删 `OVMF_VARS.fd`（等于重置 NVRAM，启动时会重建）。`rom` 一换，en0 的 MAC 就变了，而 networkd
把租约存在 `/var/lib/systemd/network/dhcp-server-lease/macos0`，池子只有一个地址，旧 MAC 占着它：
删掉那个文件再 `networkctl reconfigure macos0`。`uuid` 一换，`-currentHost` 的设置（存在
`~/Library/Preferences/ByHost/*.<硬件 UUID>.plist`）和 `sysadminctl -screenLock` 都回到默认，
第 4 步里关屏保、关锁屏那两条要重跑，不然闲置一会儿又锁上。

**一旦用这套身份登录过 iMessage，就不要再改。** 换 serial、MLB、ROM 任何一个，在 Apple
看来都是换了一台 Mac，要重新激活，容易撞上要打电话给 Apple 的 "customer code"。
重装系统可以，身份留着。

## 安装

1. 在 tank 上取 Sequoia 的 recovery，放进状态目录：

   ```sh
   osx=$(nix flake prefetch --json github:kholia/OSX-KVM/4c378a4b5e0b219783683012bec680325eb40719 | jq -r .storePath)
   cd /data/services/macos-vm
   sudo nix shell nixpkgs#python3 nixpkgs#dmg2img -c sh -c \
     "python3 $osx/fetch-macOS-v2.py -s sequoia -o . && dmg2img -i BaseSystem.dmg BaseSystem.img"
   sudo rm BaseSystem.dmg BaseSystem.chunklist
   sudo chown macos-vm: BaseSystem.img
   sudo systemctl restart macos-vm
   ```

   用 Sequoia 而不是 Tahoe：imsg 的 IMCore helper 在 Tahoe 更严的 library validation 下
   不一定注入得进去，没有 helper 就只能走 AppleScript 发送，老版本那批卡死的投递就是它。

2. 在自己机器上开 VNC：

   ```sh
   ssh -N -L 5947:127.0.0.1:5947 hank@tank
   sops -d --extract '["macos-vm"]["vnc-password"]' secrets/hosts/tank.yaml
   open vnc://localhost:5947
   ```

3. 盘是空的，默认就进 macOS Base System（重装时按住 Option 选它）。Recovery 的终端里
   `diskutil eraseDisk APFS "Macintosh HD" GPT disk0`（先 `diskutil list physical` 核对
   disk0 是那块 80G 的），然后 Reinstall macOS Sequoia。中途重启几次，安装程序自己设好
   下一次从哪启动。

4. 设置助理里**先不要登录 Apple ID**（Set Up Later → Skip，身份还没核对）。建本地管理员
   `max`，密码在 sops 的 `macos-vm/max-password`（只给人用，tank 上不装），不勾"用 Apple 账户
   重置密码"；定位、分析、Screen Time 都不要，自动更新选 Only Download Automatically。
   进桌面后，在客体自己的终端里（QEMU 的 USB 键盘会弹出键盘设置助理，直接 Quit）：

   ```sh
   # systemsetup -setremotelogin 要 Full Disk Access；SIP 关着，launchctl 直接开
   sudo launchctl enable system/com.openssh.sshd
   sudo launchctl bootstrap system /System/Library/LaunchDaemons/ssh.plist
   # 只能在图形会话里跑：经 ssh 会报 SACSetAutoLoginPassword error:22
   sudo sysadminctl -autologin set -userName max -password -
   ```

   把自己的公钥放进 `~max/.ssh/authorized_keys`，其余经 `ssh -J hank@tank max@10.234.0.2`：

   ```sh
   sudo systemsetup -settimezone Asia/Shanghai
   # 老版本的 Mac 一睡着，健康检查超时就把整个 Max 拖崩过
   sudo pmset -a sleep 0 disksleep 0 displaysleep 0 powernap 0
   sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool false
   sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool false
   sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool false
   # 不能锁屏：闲置锁上的屏会跨重启保留，自动登录之后照样锁着
   defaults -currentHost write com.apple.screensaver idleTime -int 0
   sysadminctl -screenLock off -password -
   ```

   装完先 `diskutil verifyVolume /` 和 `diskutil verifyVolume /System/Volumes/Data`。

5. 装完撤掉安装盘：`sudo rm /data/services/macos-vm/BaseSystem.img && sudo systemctl restart macos-vm`。

6. 停机钥匙。在 tank 上看公钥：`sudo cat /data/services/macos-vm/stop_key.pub`，客体里：

   ```sh
   echo 'command="sudo /sbin/shutdown -h now",restrict <公钥>' >> ~/.ssh/authorized_keys
   echo 'max ALL=(root) NOPASSWD: /sbin/shutdown -h now' | sudo tee /etc/sudoers.d/macos-vm-stop
   ```

   验证：`sudo systemctl restart macos-vm`，日志里不应出现 QEMU 被 SIGTERM 杀掉。

7. 登录 Apple ID 之前先核对：
   - `system_profiler SPHardwareDataType`：iMac19,1，serial 是 sops 里那个；
   - `ioreg -rn en0 | grep IOBuiltin`：要是 `Yes`，iMessage 只认内建网卡；
   - `csrutil status`：disabled。
   - `sysctl kern.hv_vmm_present`：要是 0（OpenCore 的内核补丁），否则 Apple ID 登录报
     "An unknown error occurred"，见 [macos-vm-apple-id](../incidents.md#macos-vm-apple-id)。

8. Messages 登录 bot 的 Apple ID（`hnkhgn@icloud.com`），过 2FA。**关卡：** 用 iPhone 给它发
   一条，在客体里手动回一条，两边都收到才往下做。报 "customer code" 就带着那串码打 Apple
   支持电话，别反复重试。

## 桥

（复活 max 仓库的 `bridge/imsg` 之后补上：`imsg` 安装与版本、Full Disk Access 和
自动化授权、`imsg launch`、LaunchAgent。）
