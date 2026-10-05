# ms7e56 显卡分工

`nixos/hosts/ms7e56/graphics.nix` 将 GNOME、OpenGL、EGL 和 Vulkan 默认绑定到
Ryzen 9 9950X 的 AMD 核心显卡，PCI 地址为 `0000:10:00.0`。RTX 5070
保留 NVIDIA 开放内核驱动及 CUDA，用于 Bonsai 等计算任务。

AMD 驱动在 initrd 中加载，Mutter 通过 udev 规则选择 AMD 为主显卡，
并忽略 PCI `0000:01:00.0` 下的全部 DRM 设备。
Mesa 的 `DRI_PRIME` 使用 PCI 地址；GLX 和 EGL 选择 Mesa；Vulkan 使用
`VK_LOADER_DRIVERS_SELECT=radeon_icd*` 选择 RADV。配置不依赖 card 编号。

Linux 启动参数 `initcall_blacklist=sysfb_init` 停用固件显示缓冲区的注册，
`module_blacklist=nvidia_drm,nvidia_modeset` 在内核中阻止加载 NVIDIA 显示模块。
`nvidia` 与 `nvidia_uvm` 继续提供计算功能。此配置在 Linux 内核启动后生效；
UEFI 和 GRUB 阶段的输出由固件决定。显卡使用原厂 250 W 功耗上限和驱动自动频率调节。

## 2026-10-05 实机验证

`just check`、`nixos-rebuild build` 与系统切换通过，随后完成整机重启。
当前 boot ID 为 `7dc119cf-c82d-4935-a157-c6cece8c5bd4`，系统为
`/nix/store/f23yky8p51f91iqj42wsc9i6pid5ykkm-nixos-system-ms7e56-26.05.20260911.21a67dc`。

- 内核日志确认 `sysfb_init` 和 `nvidia_modeset` 被黑名单阻止。
- `nvidia_drm`、`nvidia_modeset` 均未加载；5070 下没有固件显示设备。
- DRM 设备全部属于 AMD `0000:10:00.0`；GNOME 的设备句柄只包含 AMD 的
  `card0` 与 `renderD128`。设备编号是本次启动的观测值，配置继续使用 PCI 地址。
- 主力与 Hikari 均通过英文补全、中文问答、代码分析和真实主机名称工具调用，
  共 10 次 API 请求、4 组断言。测试后卸载模型，GPU 进程列表为空。
- `display-manager`、`llama-swap`、`bonsai-tailnet-gateway` 均正常运行，
  systemd 没有失败服务。

两次测量均在模型卸载、没有 CUDA 任务的状态下进行：

| NVIDIA 显存统计 | 切换前 | 重启并验证后 |
| --- | ---: | ---: |
| Total | 12227 MiB | 12227 MiB |
| Reserved | 476 MiB | 476 MiB |
| Used | 1 MiB | 0 MiB |
| Free | 11751 MiB | 11752 MiB |

可用显存实测增加 1 MiB；476 MiB 的驱动保留量保持不变。
显示帧缓冲的像素大小无法直接换算为 CUDA 可回收显存。

远程配置目录为 `~/.config/nix-config-bonsai-ninfer`，包含模型服务和显卡配置。
OpenGL/Vulkan 的默认设备设置随登录会话生效；当前用户服务管理器已同步这些变量。

完整设备检查与请求记录在该目录的 `.work/display-isolation/`。
模型参数和上下文测量见 [NInfer 部署报告](../REPORT.md)。

## 恢复显示设置

手动编辑 `graphics.nix`，删除上述两项启动参数和 5070 的
`mutter-device-ignore` 规则，执行 `just check`、`nixos-rebuild build`、
`nixos-rebuild switch`，随后重启。配置备份位于
`.work/display-isolation/backups/20261005-2335/graphics.nix`。
