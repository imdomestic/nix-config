# Ghostty：Neovide 风格光标与 pixiedust

`home/modules/ghostty/shaders/neovide-cursor.glsl` 是 Ghostty 1.3+ 的
custom shader，提供随移动方向伸缩的四角弹簧拖尾，以及沿移动路径散落、
旋转漂移、逐渐淡出的方形粒子。颜色取当前终端光标，保留应用的 block、bar、
underline 形状和原有光标文字。默认不添加辉光、彩虹或全屏滤镜。

## 配置与启用

Hank 的 home 导入 `home/modules/ghostty/neovide-cursor.nix`，Linux 启用
`my.ghostty.neovideCursor.enable`，macOS 因持续重绘成本停用。
模块只在该开关与 `programs.ghostty.enable` 同时启用时生成
`programs.ghostty.settings.custom-shader` 和
`custom-shader-animation = true`；其他用户不受影响。

GLSL 是程序资源，Nix 将其写入 store；Ghostty 配置仍全部使用 Home Manager
原生选项。模块为 macOS Metal 和 Linux OpenGL 分别设置粒子的 Y 轴方向。

按仓库的 freshness 检查流程确认 checkout 后，运行 `just hm m1elite hank`
激活本机 home，再在 Ghostty 按 `Cmd+Shift+,` 重载配置。

关闭：将 `my.ghostty.neovideCursor.enable` 改为 `false`，重新激活并重载。
该开关保留其他模块提供的 shader。

独立使用 macOS 版源文件也可以：

```ini
custom-shader = /absolute/path/to/neovide-cursor.glsl
custom-shader-animation = true
```

Linux 独立使用时将源文件默认的 `PIXIE_Y_SIGN` 改为 `-1.0`。
动画设置为 `false` 按配置文档应只在终端更新时渲染，但本机
`1.3.2-main-+91f66da24` 的 macOS vsync 路径仍会因加载了 shader 而持续重绘，
不能把这个设置当作已经验证有效的省电措施。实测和源码分析见
[事故记录](incidents.md#ghostty-shader-vsync)。
这个开关也不提供“光标移动后播放完动画再停止”的调度；在真正按需渲染的
路径上，拖尾可能停留到下一次刷新。shader 内提前返回只能减少计算，
不能停止渲染循环。

## 调节

参数位于 GLSL 顶部，默认对应 Neovide 的设置：

| 参数 | 默认 | 含义 |
|---|---:|---|
| `ANIMATION_LENGTH` | `0.150` | 长距离弹簧时间尺度，秒 |
| `SHORT_ANIMATION_LENGTH` | `0.040` | 同行两字符以内的短距离时间尺度，秒 |
| `TRAIL_SIZE` | `1.0` | 前后角的速度差，越小越少拉伸 |
| `PARTICLE_LIFETIME` | `0.5` | 最长粒子寿命，秒 |
| `PARTICLE_DENSITY` | `0.7` | 每移动一个字符高度的平均粒子数 |
| `PARTICLE_SPEED` | `10.0` | 粒子速度参数 |
| `PARTICLE_CURL` | `1.0` | 粒子运动方向的旋转量 |
| `PARTICLE_OPACITY` | `200 / 255` | 最大粒子透明度 |
| `MAX_PARTICLES` | `96` | 单次移动粒子上限 |

`PARTICLE_DENSITY = 1.5` 会让尘粒更明显；默认遵循 Neovide 的稀疏效果。
弹簧使用 `omega = 4 / duration` 的临界阻尼解，达到亚像素阈值才结束，
因此 150 ms 是响应时间尺度，不是强制截断时间。

## 与 Neovide 的边界

这是近似实现，不能称为完整移植：

- Ghostty 只提供当前和上一次光标及最近变动时间，`iChannel0` 是当前终端画面，
  没有上一帧状态反馈。新移动会替换旧轨迹，无法保留更早的粒子、弹簧速度或
  小距离移动的粒子数量余数；连续转弯时尤为明显。这里以确定性随机数和
  随机舍入维持平均粒子密度。
- Neovide 可以在绘制文字前移动光标；shader 拿到的画面已经含有原生光标。
  为避免擦掉带颜色的文字，本实现保留真实光标，只绘制额外拖尾；短距离移动
  也使用前角先到、后角跟随的形变，而不是移动整个原生光标矩形。
- Ghostty 的 bar/underline uniform 是光标 glyph 尺寸，不是完整字符格尺寸。
  条形光标的字符宽度和下划线光标的字符高度需要按约 1:2 的比例估算。
- 隐藏、失焦、空尺寸初始光标、hollow/lock、同位置颜色更新不生成特效。
  粒子使用有寿命的小方块和线性淡出，保留背景的预乘 alpha。
- shader 不知道 Neovim 模式、窗口或命令行；终端程序的光标移动也会出现特效。

## 2026-09-30 验证

- 本机 Ghostty：`1.3.2-main-+91f66da24`，Metal；当前配置背景透明度为 0.85。
- 用该 Ghostty revision 的真实 `shadertoy_prefix.glsl`，经 glslang 编译到
  SPIR-V，再由 SPIRV-Cross 转为 MSL，并由 Apple M1 Pro 的 Metal 驱动编译、
  离屏渲染。覆盖 block/bar/underline、短移动、斜向移动和粒子寿命。
- 156 帧渲染检查中，隐藏、失焦、初始位置、静止、hollow、lock、重新聚焦但
  尚未移动、动画完全结束的输出与输入逐字节一致；透明背景满足预乘 alpha。
  同时检查原生光标区域和远离轨迹区域不变，并目视检查渲染图片。
- `hank@m1elite` Home Manager activation derivation 求值、生成的 Ghostty
  配置构建、`ghostty +validate-config` 通过。未运行 switch。
- 电脑控制工具拒绝访问 Ghostty，因此没有进行真实 Ghostty 窗口加载和交互验收。
  离屏预览使用合成终端底图，不能当作 Ghostty 运行截图。

参考：

- [Neovide 光标实现](https://github.com/neovide/neovide/blob/main/src/renderer/cursor_renderer/mod.rs)
- [Neovide 粒子实现](https://github.com/neovide/neovide/blob/main/src/renderer/cursor_renderer/cursor_vfx.rs)
- [Neovide 弹簧实现](https://github.com/neovide/neovide/blob/main/src/renderer/animation_utils.rs)
- [Ghostty custom-shader 接口](https://ghostty.org/docs/config/reference#custom-shader)
- [本机 Ghostty shader uniforms](https://github.com/ghostty-org/ghostty/blob/91f66da24/src/renderer/shaders/shadertoy_prefix.glsl)
