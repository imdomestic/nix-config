# fendada 的 Pi

`home/fendada/profiles/dev.nix` 加载独立的 `modules/pi`；不会导入 hank 或
linwhite 的 home 模块。模型目录和价格初始参照 hank 的配置，之后独立维护。

- Pi 二进制来自 flake 的 `llm-agents` input。
- `~/.pi/agent/models.json` 由 Home Manager 生成，包含 CLIProxy、Rewind、
  OpenCode 和 NInfer；认证信息不进入 Nix store。
- CLIProxy 的 key 由 `modules/sops` 从 `secrets/clients/cliproxy.yaml` 解密，
  Pi 在请求时通过 `!cat` 读取。
- Gemini 走 agy-proxy 的原生 `agy/*`（`google-generative-ai`），key 来自
  `secrets/clients/agy-proxy.yaml`。没有 Hydrogen XHigh：Pi 1.6.0 的 Google 适配器
  遇到 `xhigh` 直接报 `Unsupported Google thinking level mapping`（2026-11-25 离线实测），
  linwhite 靠一个扩展绕过，这里不带扩展。也没有 `agy-completions/*`：Pi 1.5.2 时它带工具的
  第二轮会 400（`docs/agy-proxy.md` 的客户端一节）。
- 没有复制其他账户的扩展、主题或默认模型偏好。

## 新机器的认证

模型出现在 `/model` 中不代表认证已经成功。机器需要能访问 tailnet 上的服务，
并具备已经授权给 fendada 的私钥，任选一种：

- SSH 私钥：`~/.ssh/id_ed25519`；
- age 私钥：`~/.config/sops/age/keys.txt`。

私钥和所在目录应分别使用 `0600`、`0700` 权限；不要将私钥提交到仓库，
也不要为解决本机缺 key 而扩大其他账户或服务的密钥权限。
新生成的随机私钥不能解开现有密文，需要另行授权和重新加密。

放好匹配的私钥后，以 fendada 身份运行：

```sh
systemctl --user restart sops-nix.service
cd ~/.config/nix-config
home-manager switch -b backup --flake '.#fendada@7945hx-wsl'
pi --list-models
```

`systemctl --user status sops-nix.service` 可检查解密状态；不要打印解密后的 key。
Pi 已打开时用 `/model` 重新加载模型目录。
