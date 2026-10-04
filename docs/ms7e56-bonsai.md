# ms7e56 本地 Bonsai 服务

系统配置使用 `nixos/modules/bonsai-ninfer.nix`，远程访问使用
`nixos/modules/bonsai-tailnet.nix`，独立 Home Manager 使用
`home/modules/opencode/local-bonsai.nix`。模型参数位于 `lib/bonsai-models.nix`。

两个模型均使用 NInfer、NVFP4 KV、174080 上下文和 MTP K=3。
OpenCode 默认使用 `local-bonsai/bonsai-main`，`aggressive` agent 使用
`local-bonsai/bonsai-hikari`。

使用方法、模型校验值、性能测量、网络认证、验证结果和恢复命令见
[部署报告](../REPORT.md)。构建与转换记录见
[运行记录](incidents.md#ms7e56-bonsai-ninfer-174080)，配置决定见
[方案记录](decisions.md#ms7e56-bonsai-ninfer)。
