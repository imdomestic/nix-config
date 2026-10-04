# ms7e56 本地 Bonsai 服务

配置入口是 `nixos/hosts/ms7e56/default.nix`。系统服务与独立 Home Manager 分别导入 `nixos/modules/local-llm.nix` 和 `home/modules/opencode/local-bonsai.nix`，模型信息统一维护在 `lib/bonsai-models.nix`。

RTX 5070 用于 CUDA 计算，GNOME 与默认 3D 渲染由 AMD 核心显卡负责。配置及实机检查见 [显卡分工](ms7e56-gpu.md)。

## 使用

OpenAI 兼容端点为 `http://127.0.0.1:8080/v1`，模型 ID 为 `bonsai-main` 和 `bonsai-hikari`。llama-swap 根据请求的 `model` 自动卸载当前模型并加载目标模型。服务随系统启动，首次请求负责加载模型。

opencode 默认模型为 `local-bonsai/bonsai-main`。使用 `opencode --agent aggressive` 或 `opencode run --agent aggressive '问题'` 选择 Hikari。原有 provider 和 agent 继续保留。

```sh
sudo systemctl start llama-swap
sudo systemctl stop llama-swap
systemctl status llama-swap bonsai-models
journalctl -u llama-swap -n 100 --no-pager
curl --fail http://127.0.0.1:8080/v1/models
```

模型保存在 `/var/lib/llm-models/bonsai2/`。`bonsai-models.service` 根据固定的 Hugging Face revision 下载文件，检查精确字节数和完整 SHA256，再将 `.partial` 文件改为正式文件。已有完整文件会重新校验；下载中断后可执行 `sudo systemctl restart bonsai-models llama-swap` 继续下载。

## 引擎与参数

使用 PrismML `llama.cpp` 的 `prism-b10743-adfffbe`，commit `adfffbe41b2cabcd51fff326ab045662265062bb`，源码 NAR hash 为 `sha256-SNBAC+dNTwQxpGmKyG7i/8eqCNg6985DXtqGbzWgwFA=`。引擎通过 Nix derivation 构建，使用 CUDA 12.9 和 `CMAKE_CUDA_ARCHITECTURES=120`。

两个模型均使用 32768 token 上下文、单个推理槽、全部层 GPU 卸载、Flash Attention、q8_0 K/V cache、batch 512、ubatch 256、Jinja 模板。输出上限为 16384 token。采样参数为 temperature 1.0、top_p 0.95、top_k 20、min_p 0.05、repeat_penalty 1.0。

主力模型启用 `--spec-type draft-mtp --spec-draft-n-max 2`。两个模型均启用 thinking 和 medium effort；Hikari 在 llama-swap 请求过滤器中固定 `reasoning_effort=medium` 和相应的 `chat_template_kwargs`。opencode 模型与 aggressive agent 同时声明 `reasoningEffort=medium`。

引擎使用 `--reasoning on --reasoning-effort medium --no-ui`。上下文长度包含输入、推理过程和输出；输入较长时，剩余输出空间会相应减少。

Hikari 为作者标注的 preview v0.1。两份 GGUF 内嵌的 chat template 由 `--jinja` 使用，模型为文本输入，未配置视觉投影文件。

## 2026-10-04 验证记录

运行环境：NixOS `26.05.20260911.21a67dc`，nixpkgs revision `21a67dc470149f337cecafbe965d8d252a390518`，RTX 5070，驱动 `595.71.05`，开源 NVIDIA 内核模块，显存总量 12227 MiB。CUDA 12.9 通过引擎包的 `cudaSupport = true` 启用，使用现有 `cache.nixos-cuda.org` 缓存。llama-swap 为 224，opencode 为 1.18.34。

两份模型已验证完整 SHA256，架构均为 `qwen35`。主力文件包含 866 个张量，其中有 15 个 `blk.64.*` MTP 张量；Hikari 文件包含 851 个张量。

| 模型 | 文件 | 精确字节数 | SHA256 |
| --- | --- | ---: | --- |
| bonsai-main | Ternary-Bonsai-2-27B-Abliterated-v2-PQ2_0-MTP.gguf | 7657489696 | a4e4c7b578131595c1694354bd6c74d00920df1f5082647a6126899753ebebf8 |
| bonsai-hikari | Ternary-Bonsai-2-27B-Abliterated-PQ2_0.gguf | 7206168928 | 41a362f422b70a8c2dc74a3cc14447ad0ea702c440f0dbe41dc1796da7b7e342 |

全部 10 项 API 检查通过：模型列表、三次换载请求、两个模型的真实工具调用往返、Hikari 服务端参数覆盖、两个模型的长输入测试及显存检查。中文输出通过检查，工具调用参数为合法 JSON。Hikari 参数覆盖测试向实际端点发送关闭 thinking 与不支持的 effort，服务仍按固定配置生成独立的 reasoning 内容及中文正文。

opencode 使用原有配置和插件完成 `read → edit → read`，给真实 `receipt.py` 增加折扣参数；原有调用、折扣、全额折扣、空列表及参数范围检查共 5 项测试通过。`aggressive` agent 完成中文软件分析对话。原有 `cliproxy`、`ninfer` provider 和 API key 文件引用保留，原默认模型 `ninfer/qwen3.8-27b` 继续可选。

| 主力模型测速 | 生成速度中位数 | 首 token 延迟中位数 | 显存峰值 |
| --- | ---: | ---: | ---: |
| MTP 关闭 | 68.59 tok/s | 0.153 秒 | 8359 MiB |
| MTP 开启 | 95.99 tok/s | 0.170 秒 | 9295 MiB |

测速包含一次预热和三组相同提示，分别生成 384 token，使用贪心解码、固定种子 `20261004`、关闭 prompt cache。速度为 llama-server 返回的生成阶段统计，首 token 包含 reasoning token。该组测试的 MTP 中位数提升 39.94%；不同文本的提升幅度会变化。Hikari 中文问答实测生成速度为 68.58 tok/s。

main → Hikari 换载请求的首 token 延迟为 1.51 秒，Hikari → main 为 2.57 秒；这些时间包含卸载、加载和短提示处理。对应中文正文首次出现于请求开始后的 6.92 秒与 6.19 秒，之前输出 thinking。首次切换到主力的首 token 延迟为 3.25 秒。

两个模型均完成 31000 token 输入并继续生成 64 token，实际请求耗时分别为主力 25.05 秒、Hikari 24.74 秒。验证期间总显存峰值 9295 MiB，最低余量 2932 MiB（约 2.86 GiB），未发生 OOM。API 端口 8080 和当前后端端口均只绑定 `127.0.0.1`。

NixOS 构建、两台机器上的 `just check`、独立 Home Manager 预检查、Nix 格式检查和实际 opencode 配置加载检查均通过。配置使用固定 PrismML fork 支持 PQ2_0 与 MTP，主力文件为指定的 v2 MTP 文件。部署同时应用仓库已有的 `b650 → taipan` 地址更新及 `973aa36` 的共享开发工具配置更新。Bonsai 的配置变更与这些仓库更新分别记录在 diff 中。

## 修改与验证

本机仓库独立工作目录为 `~/.config/nix-config-bonsai`。修改配置后，先构建与检查，再分别激活系统和 Home Manager：

```sh
cd ~/.config/nix-config-bonsai
export TMPDIR="$HOME/.work/bonsai/tmp"
just check
nixos-rebuild build --flake .#ms7e56 --max-jobs 2 --cores 6
just hm-dry ms7e56 linwhite
nixos-rebuild --sudo switch --flake .#ms7e56
just hm ms7e56 linwhite
```

实际接口验证使用 `scripts/verify-bonsai.py`，检查模型列表、中文流式回答、换载、真实工具调用往返、31000 token 输入与显存余量。`scripts/bench-bonsai.py` 使用同一模型、相同提示和贪心解码，分别启动 MTP 关闭与开启的服务，进行预热和三组测速。测试环境由 `scripts/bonsai-test-env.nix` 声明。

```sh
nix build --impure --file scripts/bonsai-test-env.nix --out-link "$HOME/.work/bonsai/python"
"$HOME/.work/bonsai/python/bin/python" scripts/verify-bonsai.py \
  --output "$HOME/.work/bonsai/verification" --long-context
nix eval --json .#nixosConfigurations.ms7e56.config.services.llama-swap.settings \
  > "$HOME/.work/bonsai/llama-swap-settings.json"
sudo systemctl stop llama-swap
"$HOME/.work/bonsai/python/bin/python" scripts/bench-bonsai.py \
  --settings "$HOME/.work/bonsai/llama-swap-settings.json" \
  --output "$HOME/.work/bonsai/benchmark"
sudo systemctl start llama-swap
```

## 恢复

恢复上一代 NixOS 配置：

```sh
sudo nixos-rebuild switch --rollback
```

2026-10-04 部署前的 Home Manager generation 为 `/nix/store/vzkrsr9776mlrgmck9pm5jfaj4vj8z62-home-manager-generation`，恢复该用户配置可执行：

```sh
/nix/store/vzkrsr9776mlrgmck9pm5jfaj4vj8z62-home-manager-generation/activate
```

部署前配置备份位于 `~/.work/bonsai/backups/20261004/`，包含 opencode 原始配置和系统、Home Manager 路径。恢复指定系统 generation 时，使用该目录记录的 `system.path`。永久停用本模块，需要编辑主机入口，移除上述系统与 Home Manager 两项 import，再分别构建和激活。模型文件独立保留。

## 上游资料

- [主力模型卡](https://huggingface.co/BoldingBuilds/Ternary-Bonsai-2-27B-Abliterated-v2-PQ2_0-MTP-GGUF/blob/main/README.md)
- [Hikari 模型卡](https://huggingface.co/Hikari07jp/Ternary-Bonsai-2-27B-Abliterated-GGUF/blob/main/README.md)
- [PrismML 引擎](https://github.com/PrismML-Eng/llama.cpp/tree/prism-b10743-adfffbe)
- [llama-swap v224 配置说明](https://raw.githubusercontent.com/mostlygeek/llama-swap/v224/config.example.yaml)
- [opencode provider 文档](https://opencode.ai/docs/providers/)
- [opencode agent 文档](https://opencode.ai/docs/agents/)
