# seraph SSH 计算节点

`nixos/hosts/seraph/compute.nix` 将系统设为通过 SSH 使用的计算节点，
默认启动目标为 `multi-user.target`。GNOME、GDM、Xserver、音频、打印和
蓝牙服务均停用，Home Manager 使用终端环境和开发工具。

AMD Granite Ridge 核显的 PCI 地址为 `0000:10:00.0`，RTX 5070 为
`0000:01:00.0`。Linux 启动参数为：

```text
initcall_blacklist=sysfb_init
module_blacklist=amdgpu,radeon,nvidia_drm,nvidia_modeset
```

两张显卡的显示驱动和固件显示缓冲区均停用。NVIDIA 的 `nvidia`、
`nvidia_uvm`、开放内核模块、595.71.05 驱动、持久化服务及容器 CDI
提供 CUDA 计算。`hardware.graphics.enable` 提供宿主机运行库目录
`/run/opengl-driver`；显示设备由上述内核配置停用。
此配置在 Linux 内核启动后生效。UEFI 固件及 GRUB 自身的启动画面独立于该配置。

当前物理显示器仍然亮着，接口断开信号和显示器进入待机尚未通过验收。
`nvidia-smi` 报告 `Display Active: Disabled`、`Display Attached: Yes`，
这些驱动状态与 Linux 设备检查只能确认图形服务及其显存占用已经停止。
Taipan 实机的全部 DP/HDMI 接口报告 `disconnected`，其 Mutter 规则用于
让 GNOME 忽略 NVIDIA；该状态不能验证插着显示器时的接口断开行为。

## 2026-10-06 实机验证

`just check`、`nixos-rebuild build`、`just hm-dry seraph linwhite`、系统切换和
Home Manager 激活均通过，随后完成整机重启。

- boot ID：`f934bee3-505a-41ce-b014-16803f841c56`。
- 系统：`/nix/store/r6h6c8fmglvfkn6d4wv94gy8n1raibxw-nixos-system-seraph-26.05.20260911.21a67dc`。
- Home Manager：`/nix/store/mk277yl3hkq06j0gbr6wh47gpfdjygp7-home-manager-generation`。
- SSH 分配并实际使用 `/dev/pts/0`；tmux、Zsh、Neovim 与 OpenCode 模型列表检查通过。
- `amdgpu`、`radeon`、`nvidia_drm`、`nvidia_modeset` 均未加载。
  系统没有 DRM 显示或渲染设备，也没有 framebuffer 设备。
- GNOME、GDM、Xorg、Xwayland、Vicinae 和音频服务进程均不存在。
  `display-manager.service` 不存在，`graphical.target` 未启动。
- SSH、Tailscale、NVIDIA 持久化服务、llama-swap 和 Bonsai 网关正常运行；
  系统和用户均没有失败的 systemd 服务。
- 主力与 Hikari 均通过英文补全、中文问答、代码分析和真实主机名称工具调用，
  共 10 次推理请求、4 组检查。测试后卸载模型，GPU 进程列表为空。

| NVIDIA 显存统计 | 改动前空闲 | 重启后空闲 |
| --- | ---: | ---: |
| Total | 12227 MiB | 12227 MiB |
| Reserved | 476 MiB | 476 MiB |
| Used | 0 MiB | 0 MiB |
| Free | 11752 MiB | 11752 MiB |

显存统计保留了驱动报告的 476 MiB Reserved；该数值不属于图形进程占用。

远程配置目录为 `~/.config/nix-config-bonsai-ninfer`，本次构建日志、设备检查、
推理请求和结果位于 `.work/compute-node/`。模型参数和上下文测量见
[NInfer 部署报告](../REPORT.md)。

## 配置恢复

改动前的主机配置备份位于 `.work/compute-node/backups/20261006-0355/`。
需要恢复时，使用文件编辑工具根据备份恢复 `default.nix`、`graphics.nix` 和
`system.nix`，移除本次新增的 `compute.nix` 与 `home.nix`，再执行
`just check`、`nixos-rebuild build --flake .#seraph` 和
`just hm-dry seraph linwhite`。检查通过后切换系统、激活 Home Manager 并重启。
