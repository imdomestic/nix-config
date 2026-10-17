# encore 散热配置

encore 使用 ROG Zephyrus M16 GU603ZM、Intel Core i7-12700H 和 RTX 3060 Laptop GPU。
配置位于 `nixos/hosts/encore/cooling.nix`，由独立的 NixOS 系统配置管理。

## 风扇曲线

`services.asusd` 管理 CPU 和 GPU 风扇，两只风扇均使用以下曲线。
quiet、balanced、performance 三个档位使用相同曲线。

| 温度 | 风扇 PWM 比例 |
| --- | --- |
| 30°C | 约 35% |
| 40°C | 50% |
| 50°C | 65% |
| 60°C | 80% |
| 65°C | 90% |
| 70°C | 100% |
| 80°C | 100% |
| 90°C | 100% |

asusd 随系统启动，在电源档位切换时应用对应曲线。曲线由硬件控制器执行。
GNOME 的电源档位及 CPU EPP 由 power-profiles-daemon 管理。
持续送风会增加低负载时的噪声。

## CPU 功耗和温度

`services.throttled` 管理 CPU 功耗及温度目标，每隔 5 秒重新应用设置，
并处理电源来源变化。CPU 的电压和频率由硬件在限制范围内调节。

| 电源来源 | 长期功耗 PL1 | 短期功耗 PL2 | 温度控制目标 |
| --- | --- | --- | --- |
| 接通电源 | 35W | 45W | 80°C |
| 电池供电 | 25W | 35W | 80°C |

PL1 时间窗口为约 2 秒，PL2 时间窗口由硬件量化为约 2.44 毫秒。
功耗及温度限制会降低高负载时的 CPU 性能，设置以降低温度为目标。
两个服务都在配置变化时自动重新启动。

## 2026-10-17 验证

在接通电源、balanced 档位下使用 `stress-ng --cpu-method matrixprod --verify`
进行实际计算，每隔约 2 秒读取 CPU 温度、GPU 温度、风扇转速和 RAPL 能耗计数。

| 测试 | 时间 | CPU 平均 / 最高 | GPU 平均 / 最高 |
| --- | --- | --- | --- |
| 4 个 CPU 工作进程 | 120 秒 | 76.4°C / 82°C | 44.1°C / 46°C |
| 20 个 CPU 工作进程 | 180 秒 | 72.3°C / 74°C | 47.3°C / 48°C |
| 负载结束后的降温采样 | 60 秒 | 47.8°C / 59°C | 43.8°C / 48°C |

两个计算测试均通过 stress-ng 的结果校验。持续负载时 CPU 功耗约 35W，
CPU 风扇约 6400 RPM。80°C 是温度控制目标，测试中最高瞬时采样值为 82°C。

已逐一验证 quiet、balanced、performance 档位的两只风扇全部八个曲线点、
MSR 和 MMIO 的 PL1/PL2，以及全部 20 个逻辑处理器的温度目标寄存器。
重新启动 asusd 和 throttled 后设置保持生效；两个服务均随系统启动。
Chorus、k3s 运行正常，系统没有失败的 systemd 服务。
仓库中的 20 个 NixOS 主机和 4 个 nix-darwin 主机通过配置求值。

## 检查命令

在 encore 上执行：

```sh
systemctl status asusd throttled
asusctl fan-curve --get-enabled
powerprofilesctl get
cat /sys/class/powercap/intel-rapl:0/constraint_0_power_limit_uw
cat /sys/class/powercap/intel-rapl:0/constraint_1_power_limit_uw
journalctl -b -u throttled
```

接通电源时，两个功耗读数应分别为 `35000000` 和 `45000000`，单位为微瓦。
风扇曲线的每个档位都应包含已启用的 CPU 和 GPU 风扇。

接口说明见 [asusctl 手册](https://raw.githubusercontent.com/OpenGamingCollective/asusctl/main/docs/usage/asusctl.md)、
[Linux powercap 文档](https://cdn.kernel.org/doc/html/latest/power/powercap/powercap.html)
和 [throttled 文档](https://raw.githubusercontent.com/erpalma/throttled/master/README.md)。
