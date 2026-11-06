# Safari 的 Ctrl+Tab MRU

`pkgs/safari-mru` 是不显示窗口、Dock 图标或菜单栏图标的原生后台程序。
只使用 macOS 自带的 Cocoa、Accessibility 和 Carbon；不需要 Safari 扩展。
Hank 的 `gui-darwin` home 加载 `home/hank/modules/safari-mru.nix`，由用户 launchd 启动。

## 行为

- `Ctrl+Tab` 立即切到最近使用的另一个标签。
- 保持 Ctrl 按下，继续按 Tab 沿本次按键开始时的 MRU 顺序前进；Shift+Tab 反向。
- 松开 Ctrl 后，只有最后停留的标签被提升到 MRU 首位，连续独立按两次可以来回切。
- 仅在 Safari 前台、当前窗口有至少两个可识别标签时注册快捷键。
  地址栏获得焦点时也可用；切到其他 app 后释放快捷键。
- 每个窗口独立维护内存中的历史；首次启动不知道此前的访问顺序，未访问标签以标签栏顺序补齐。
  切到其他 app 时保留记录；Safari 退出重启或程序重启后重新开始记录。
- 按 AX 元素身份识别标签，不读取网页内容、不保存 URL，也不按标题或 URL 合并标签。
  关闭标签、切换标签组会移除失效元素；隐藏标签栏而导致 AX 不提供标签时保留 Safari 默认行为。

## 构建与启用

这是独立 Home Manager 配置，系统 rebuild 不会启用它。先运行：

```sh
just hm-dry praxic hank
```

需要启用时运行 `just hm praxic hank`。首次还需在 macOS **系统设置 → 隐私与安全性** 中授权：
macOS 27 的页面叫 **Device Control and Data Access**，早期版本叫 **辅助功能 / Accessibility**。
在这个页面添加 `~/Applications/Home Manager Apps/Safari MRU.app` 并允许它。
可运行 `safari-mru --request-access` 请求系统权限提示；终端可能继承自身的权限，若没有出现提示则直接在设置中添加 app。
若 agent 已经运行，授权后切回 Safari 会触发重新检查，不用重新启用 home。不要同时手动运行第二个常驻实例。
没有授权时程序等待并写一条日志，不拦截按键、不反复弹窗。

程序使用本地 ad-hoc 签名；Nix 升级后若 macOS 不再认可原授权，需要在辅助功能列表中移除旧条目、
重新添加新的 `Safari MRU.app`。不绕过系统授权。

只读检查当前 Safari 窗口的标签识别（不会切标签，也不输出标题或 URL）：

```sh
safari-mru --inspect
tail -n 30 ~/Library/Logs/safari-mru.log
```

暂停：`launchctl bootout gui/$(id -u)/org.nix-community.home.safari-mru`。
重新启动可重新启用 home，或 `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.nix-community.home.safari-mru.plist`。

## 实现边界

没有周期性定时器。应用切换、启动退出、唤醒与会话恢复通过 NSWorkspace 通知处理；
Ctrl 松开通过 NSEvent 的修饰键变化事件提交本次切换。
在 Safari 应用元素上订阅 AXValueChanged、AXCreated、AXUIElementDestroyed、AXSelectedChildrenChanged、
窗口焦点和 sheet 通知，也能接收到程序启动后新标签的事件。
已知标签选中时直接记录 MRU；结构变化通知合并到下一次主队列处理后才扫描标签树。
每次按 Ctrl+Tab 仍立即读取完整列表、剔除关闭的标签；这是按键触发的校验，不是后台轮询。
忽略网页控件的 value/创建事件，不因页面文字变化重新扫描所有标签。
Safari 若不发送某个必要通知，会影响对手动切换历史的记录；不以常驻轮询掩盖这类兼容性问题。
程序不改变 Safari 关闭标签时默认选中哪个标签，也不跨窗口或跨标签组跳转。
Safari 改动 AX 层级可能需要调整识别；目前只接受 `AXTabButton`，并避开网页的 AX 子树。
初版轮询的测量与改动原因：`docs/incidents.md#safari-mru-event-driven`。

纯 MRU 状态测试在 Nix 构建的 checkPhase 运行，覆盖按住与松开、反向、手动切换、拖动、关闭及标签组切换。
`--inspect` 只能证明读取成功；快捷键接管、实际切换与权限仍需在登录的 macOS 桌面验收。

交互集成测试会建立单独的 Safari 窗口，用三个相同的 Start Page 测试真实快捷键，结束时关闭窗口、
停止测试进程并恢复原来的窗口和前台应用。运行期间请暂停使用 Safari，否则真实输入会改变测试状态。
需要本机 Xcode Command Line Tools，且终端已获得辅助功能权限：

```sh
nix build .#safari-mru
/usr/bin/swift pkgs/safari-mru/test-integration.swift "$PWD/result/bin/safari-mru"
```

交互测试还验证程序启动后创建的新标签，避免按键时即时扫描掩盖通知订阅缺失。
测试由已授权的 Rex 终端运行；launchd 常驻实例仍需启用 Home Manager 并单独核对辅助功能授权。

2026-11-06：事件驱动版已通过构建、纯状态测试及配置求值。
Owner 已手动 switch 启用当前未提交工作区版本，launchd 服务运行中，日志显示等待辅助功能权限。
实际通知覆盖与快捷键验收尚未完成；授权后继续验证，再提交推送。
