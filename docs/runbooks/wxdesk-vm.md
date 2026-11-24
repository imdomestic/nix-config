# tank 上的微信虚拟机（maxx 的微信）

maxx 的微信是 tank 上一台 NixOS 虚拟机里的官方 Linux 微信，由
[wxdesk](https://github.com/HCHogan/wxdesk) 读窗口、操作窗口，maxx 经 TCP 连它。
为什么这么做见 [wxdesk-vm](../decisions.md#wxdesk-vm)，配置在 `hosts/tank/wxdesk-vm.nix`，
虚拟机本身是 wxdesk 仓库的 `nix/vm.nix` 和 `vm/guest.nix`。

## 布局

- `wxdesk-vm.service`，以 `wxdesk-vm` 用户跑 QEMU/KVM，4 vCPU、4 GiB，QEMU 的用户态网络。
  客体用 tank 的 `/nix/store`。
- tank 上只听 `127.0.0.1`：`10022` 是客体的 ssh，`15901` 是 VNC，`17710` 是 wxdesk。
- 状态在 `/var/lib/wxdesk-vm`：`disk.qcow2` 是客体的盘，**微信的登录在里面**；`ssh-key`
  是进客体的钥匙；`booted` 指向这次启动的客体，是 GC root。
- sops：`secrets/hosts/tank-max.yaml` 的 `wxdesk/token`（maxx 也读它）和 `wxdesk/env`
  （`WXDESK_GROUP=<群名>`、`WXDESK_ME=maxx`）。客体启动时由 QEMU 的 fw_cfg 交给它。
- 客体里：`wx-desktop`（Xvnc :1 + openbox + 微信，用户 `wx`）和 `wxdesk`。

## 部署和重启

部署**不重启**这台虚拟机：重启后微信可能要手机重新确认登录。换了 wxdesk 的版本、
`wxdesk/env` 或 token 之后，要它生效就手动重启，并准备好手机：

```sh
systemctl restart wxdesk-vm      # ACPI 关机，最多等 100 秒
journalctl -u wxdesk-vm -f       # 客体的串口输出
```

## 登录

微信退出了登录，或者换了一块新盘：

1. 在自己机器上 `ssh -L 15901:127.0.0.1:15901 root@tank`，VNC 连 `localhost:15901`。
2. 密码：`wxdesk-vm-ssh cat /var/lib/wxvnc/password`。
3. 用 bot 的手机扫码登录。

## 排查

```sh
wxdesk-vm-ssh                          # 以 root 进客体
wxdesk-vm-ssh journalctl -u wxdesk -f  # wxdesk 读到什么、发了什么
journalctl -u maxx | grep max_wechat   # maxx 这边：连上、断开、发送失败
```

`a11y-dump` 和 `shot` 在客体里：前者打印微信的无障碍树，后者截屏到 `/tmp/shot.png`。
微信界面改版、wxdesk 读不出东西时从这两个看起。
