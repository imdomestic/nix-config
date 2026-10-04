# ms7e56 显卡分工

`nixos/hosts/ms7e56/graphics.nix` 将 GNOME、OpenGL、EGL 和 Vulkan 默认绑定到
Ryzen 9 9950X 的 AMD 核心显卡，PCI 地址为 `0000:10:00.0`。RTX 5070
保留 NVIDIA 开放内核驱动及 CUDA，用于 Bonsai 等计算任务。

AMD 驱动在 initrd 中加载，Mutter 通过 udev 规则选择 AMD 为主显卡。
Mesa 的 `DRI_PRIME` 使用 PCI 地址；GLX 和 EGL 选择 Mesa；Vulkan 使用
`VK_LOADER_DRIVERS_SELECT=radeon_icd*` 选择 RADV。配置不依赖 card 编号。

NVIDIA 的 KMS 设置关闭，`nvidia_drm` 和 `nvidia_modeset` 列入内核模块黑名单。
`nvidia` 与 `nvidia_uvm` 继续提供计算功能。显卡使用原厂 250 W 功耗上限和
驱动自动频率调节。实际计算速度取决于模型、运算方式、温度和负载。

## 2026-10-04 实机验证

- 系统构建及全部 20 个 NixOS、4 个 Darwin 配置求值通过。
- 图形会话重启后，Mutter 日志确认 AMD 是主显卡，并使用 AMD 的 GBM renderer。
- EGL 报告 AMD 硬件渲染，OpenGL 4.6、OpenGL ES 3.2；Vulkan 仅列出 AMD RADV。
- `glmark2-gbm --off-screen --validate` 的 27 个可比对场景通过，另外 6 个场景
  由程序标记为没有验证规则。800×600 的 Phong 和 terrain 场景分别持续运行
  10 秒，实测 10740 FPS 和 341 FPS。
- `glmark2-es2-gbm` 使用 AMD。其默认 `mediump` shader 的 conditionals、function、
  loop 共 6 项像素比对超出 glmark2 的参考阈值；例如灰度值为 27，参考值为 37。
  OpenGL 对应场景全部通过。这组 GLES 像素检查存在上述限制。
- `nvidia_drm`、`nvidia_modeset` 均未加载，NVIDIA 显示状态为 Disabled，进程列表
  仅包含 CUDA 推理。相同模型保持加载时，显存使用从 9289 MiB 降至 9151 MiB。
- Bonsai 主力模型的真实中文请求生成 381 token，生成阶段速度 99.57 token/秒，
  请求耗时 3.94 秒，测试显存峰值 9155 MiB。该数据是一次短请求的测量值。
- `llama-swap` 和 `llama-server` 的进程保持运行，服务重启次数为零；控制台中的
  opencode 进程继续运行。机器 boot ID 保持一致，systemd 没有失败服务。
- 启动配置已更新；`modprobe --dry-run --use-blacklist` 确认两个 NVIDIA 显示模块
  不会通过黑名单感知的模块加载流程加载。本次通过在线切换验证，没有重启整机。

远程配置目录为 `~/.config/nix-config-bonsai`，包含模型服务和显卡配置。
OpenGL/Vulkan 的默认设备设置随登录会话生效；当前用户服务管理器已同步这些变量。
