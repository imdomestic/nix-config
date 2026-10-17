# encore 内置键盘

ROG Zephyrus M16 GU603ZM 的内置键盘使用 ASUS N-Key 控制器，USB 标识为
`0b05:19b6`，由 `hid_asus` 驱动处理。

## 驱动配置

`nixos/hosts/encore/keyboard.nix` 通过 `boot.extraModulePackages` 安装
`pkgs/hid-asus-handshake`。该软件包使用当前内核的源码和构建依赖，应用
Linux 上游的
[键盘握手修复补丁](https://github.com/torvalds/linux/commit/e82ae34af29e910c96d33c8b3a90c60e27f1625e.patch)，
构建 `hid-asus.ko` 并安装到模块目录的 `updates/`，由 depmod 优先选择。

修复只用于 Linux 6.18.49 至 6.18.53。升级到已包含补丁的 6.18.54 或更新版本后，
NixOS 自动停止添加这个模块。

## 2026-10-17 验证

encore 使用 Linux 6.18.50。内核初始化键盘时报告
`Asus failed to request functions: -75`，背光接口未能注册。
这一版本读取键盘功能报告时只分配 16 字节，而设备的响应超过这个长度。
上游修复将缓冲区扩大到 64 字节，并检查握手响应。
Linux 维护者确认该修复已进入
[6.18.54](https://marc.info/?l=linux-input&m=179077066397990&w=3)。

修复已经写入系统配置，并在运行中的系统加载。四个 ASUS HID 接口均绑定到
`asus` 驱动，键盘输入设备正常注册，keyd 已识别键盘且配置检查通过。
`/sys/class/leds/asus::kbd_backlight` 已恢复，亮度等级 0、1、2、3 的实际写入及
读取检查均通过。asusd 能够完成键盘灯光模式和电源状态初始化。

使用者已确认内置键盘能够正常输入。UPower 和 GNOME 电源组件已经重新检测
热加载后出现的背光设备。GNOME 能够读取四个亮度等级，`StepDown`、`StepUp`
以及亮度属性设置均能改变内核中的实际亮度值。
使用者已进一步确认背光能够点亮，亮度快捷键也正常工作。

## 检查命令

```sh
modinfo -b /run/current-system/kernel-modules -n hid_asus
cat /sys/class/leds/asus::kbd_backlight/brightness
journalctl -b -k | rg 'asus|19B6'
journalctl -b -u keyd
```

模块在当前系统中的路径应位于 `updates/hid-asus.ko`。默认 `modinfo` 查询的是
本次启动使用的模块目录；热加载后，应使用上面的显式目录检查已部署配置。
