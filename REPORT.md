# seraph Bonsai NInfer 部署记录

日期：2026-10-05。配置分支：`feat/seraph-bonsai-ninfer`。

服务器已经部署，两个模型的正式服务验证通过。aegis 主仓库已合并 NInfer 配置，
独立 Home Manager 已激活，本地 OpenCode 能够使用两个模型。
显卡模块、NInfer 转换输入、模板和当前运行产物保留。

## 固定版本与产物

| 项目 | 实际值 |
| --- | --- |
| 系统 nixpkgs | `21a67dc470149f337cecafbe965d8d252a390518` |
| NInfer | `CraneBW/ninfer-ternary-bonsai-ada`，`9c875f710c459768468d74632e796d782a7e98fc` |
| GPU / 驱动 | RTX 5070，595.71.05 开放内核驱动，CUDA 13.1.2 容器 |
| 编译 | `sm_120a`，48 SM，FFmpeg，6 个并行编译任务，磁盘 TMPDIR |
| 模板 | Qwen3.8-27B v2，HF revision `dc370fb6295a` |
| 转换环境 | Nix 声明的 Python 3.11.15、NumPy 2.3.4、CPU Torch 2.11.0 |
| 镜像 | `localhost/ninfer:bonsai-9c875f71-sm120a-high` |
| 镜像 ID | `ec1fff5213c2388a98b4e99719f0546797d699d6624090d847d3c3af5a64b5ac` |
| OCI SHA256 | `1f7cd72d8a31a42de88f6ac77dd4ee3096e3955e7d4b66b35e3616bd3e4cebaf` |

主力输入来自 `BoldingBuilds/Ternary-Bonsai-2-27B-Abliterated-v2-PQ2_0-MTP-GGUF`，
revision `e25d197aa62ce0a2f685fc65d76a41b2416c5e66`，使用其中的
`Ternary-Bonsai-2-27B-Abliterated-v2-PQ2_0.gguf`。Hikari 输入来自
`Hikari07jp/Ternary-Bonsai-2-27B-Abliterated-GGUF`，revision
`e7f6daf95ab820ef8de7d8f5e883d95d546ab02c`，文件
`Ternary-Bonsai-2-27B-Abliterated-PQ2_0.gguf`。

两份 GGUF 均为 7206168928 字节、851 个张量。输入 SHA256 分别为：

- 主力：`b284cbc6cb6c2894eb3d4181d805b966948128b2add9627dbd7d1e691724b3bb`
- Hikari：`41a362f422b70a8c2dc74a3cc14447ad0ea702c440f0dbe41dc1796da7b7e342`

产物位于 `/var/lib/bonsai-ninfer/models/`，各为 10533732876 字节：

| 文件 | SHA256 |
| --- | --- |
| `bonsai-main-e25d197aa62ce0a2.ninfer` | `244e513ab2809e70d6cb1446ef61e20082bcda51ae3ab3def7c2a7542e47b00f` |
| `bonsai-hikari-e7f6daf95ab820ef.ninfer` | `3674e71fc9016550df976c7a33460e95bcfe8bbfafe80682bce36012e15f4794` |

上游几何、解码、字节往返检查全部通过。MTP、frontend、draft_head 等模板对象
按要求借用，419 个借用对象逐个核对了 SHA256。完整 embedding 解码检查需要
超过主机物理内存，配置中声明了 64 GiB 磁盘交换文件以完成完整检查。

## 最终服务参数与显存

两个模型均使用：

```text
--max-context 174080 --kv-capacity 174080 --kv-dtype nvfp4
--spec mtp --draft-tokens 3 --max-concurrency 1
--prefill-chunk 1024 --preserve-thinking --default-max-tokens 16384
--max-pending-requests 16 --pending-timeout-ms 600000
```

未启用 KVMem。NInfer 默认的主机前缀缓存保留；活动请求的 174080 KV 容量在 GPU 上。
llama-swap 的加载健康检查超时为 120 秒，OpenCode 请求超时为 600000 ms。
输入与输出共用 174080 的上下文容量；16384 是输出上限。

核显为 AMD Granite Ridge Radeon，PCI `10:00.0`；NVIDIA 为 `01:00.0`。
主机通过 SSH 使用终端，两张显卡的 Linux 显示功能均停用，
GNOME、GDM 和桌面应用已移除。2026-10-06 重启验证后，NVIDIA 空闲
占用 0 MiB、可用 11752 MiB、驱动 Reserved 为 476 MiB，GPU 进程列表为空。
两个模型的真实推理与工具调用通过，完整检查见 [计算节点记录](docs/seraph-gpu.md)。
当前物理显示器仍然亮着，接口断开信号和显示器待机尚未通过验收。

| K=3 的显存项目 | 字节 |
| --- | ---: |
| GPU 权重 | 7641154560 |
| runtime，包含 KV | 4017176832 |
| KV payload | 3409256448 |
| 启动后 CUDA 可用量 | 565248000 |

`nvidia-smi` 的总显存为 12227 MiB，驱动另有保留量；实际长输入测试峰值
11238 MiB，最小剩余 538 MiB。两个模型都能够容纳固定参数。

## 测试与速度

正式服务的 `verify-bonsai.py --long-context --service-checks` 13 组检查通过，
覆盖模型列表、Paris、中文、程序分析、真实主机名称工具往返、长输入、参数覆盖和换载。

| 模型 | 实际长输入 token | 三处记录 | 预填充秒数 | 请求总秒数 | 峰值 / 剩余 MiB |
| --- | ---: | --- | ---: | ---: | ---: |
| 主力 | 165000 | 全部正确 | 167.588 | 168.729 | 11238 / 538 |
| Hikari | 165002 | 全部正确 | 167.864 | 169.208 | 11238 / 538 |

长输入为引擎真实源代码，完整输入、来源列表、响应、SHA256 与 100 ms 显存采样均随证据交付。
正式长输入后的生成速度约为主力 102.5 tok/s、Hikari 98.0 tok/s。
三个包含生成结果的换载请求为 5.916、6.129、5.878 秒，期间每次只加载一个模型。

固定 TTL LRU cache 编码任务、medium 推理、temperature=1、top_p=0.95、top_k=20，
输出上限 16384；每组使用种子 20261005、20261006、20261007。

| 模型 | MTP K=3 中位 tok/s | MTP K=5 中位 tok/s | 选择 |
| --- | ---: | ---: | ---: |
| 主力 | 128.126 | 119.192 | 3 |
| Hikari | 126.332 | 123.895 | 3 |

12 个测速响应全部自然结束。相对旧方案记录的约 96 tok/s，分别高约 33.5% 和
31.6%；旧记录使用不同任务和采样设置，该比例用于参考。

短篇 `ppl_sample.txt` 的 PPL：主力 4.203984，Hikari 4.291636。
32k 比较使用同一份真实代码语料，64899 个输入 token、64898 个评分 token：

| 模型 | NVFP4 PPL | BF16 PPL | 相对偏差 |
| --- | ---: | ---: | ---: |
| 主力 | 1.746019 | 1.741951 | +0.234% |
| Hikari | 1.739240 | 1.736372 | +0.165% |

这项质量记录覆盖该语料，服务继续固定使用 NVFP4。

seraph 的 OpenCode 主力完成了真实 `read → edit → bash` 操作，修改问候函数并通过
3 个 unittest；测试文件 SHA256 保持不变。`aggressive` agent 完成中文程序分析对话，
服务日志确认使用 `bonsai-hikari`、medium、thinking 开启。

## 推理参数与接口

固定引擎原生支持 low、medium、xhigh。`bonsai-ninfer-high-alias.patch` 将 API 的 high
映射到原生 xhigh。主力默认 high，单次 low 和 high 请求均已从服务日志确认生效。
同一道概率题的 reasoning_tokens：high 为 130，low 为 116。

llama-swap v224 的原生 `setParams` 会覆盖客户端值。补丁增加
`setParamsIfAbsent` 和 `byPath`，分别处理 Chat 的 `reasoning_effort` 与 Responses 的
`reasoning.effort`；同时加入 Responses token 计数路由。
Hikari 在 Chat、Responses、upstream 三种入口均验证了 medium 锁定。
实际工具调用往返通过，使用严格工具解析。

## 访问、OpenCode 与当前状态

- seraph：`http://seraph.inner.imdomestic.com:8080/v1`，本机访问通过 `lo`。
- aegis：`http://seraph.inner.imdomestic.com:8080/v1`。
- 网关绑定 `100.64.0.44:8080`，只允许 `tailscale0` 上 aegis 的 `100.64.0.25`。
- SOPS 提供运行时 API key，密钥明文未写入 Nix store。缺失或错误密钥均返回 401。
- tank 的 `100.64.0.4` 访问被阻断，防火墙记录 5 个丢弃的数据包。
- seraph Home Manager 已激活，模型列表包含两个 Bonsai 模型。
- aegis 已通过网关完成两个模型的中文问答和真实工具调用往返，4 组 API 检查通过。
- aegis 主仓库 `~/.config/nix-config` 的 `main` 已合并 NInfer 分支，合并提交为 `340d16e`。
- aegis 的 `just check`、`just hm-dry aegis linwhite` 和 `just hm aegis linwhite` 均通过。
- 本地 OpenCode 模型列表包含 `local-bonsai/bonsai-main` 和 `local-bonsai/bonsai-hikari`。
- 本地主力完成 `read → edit → bash`，问候函数的三个 unittest 通过，测试文件保持原样。
- 本地 `aggressive` 完成中文程序分析对话，服务日志确认 Hikari 使用 medium 并开启 thinking。

aegis 当前 Home Manager generation 为
`/nix/store/4f2wqxxk7wqqi0ddabd492kgar40bk44-home-manager-generation`。
自动核对确认其他 provider、agent 与 OpenCode 设置保持原样。
主仓库的 seraph 系统求值结果与服务器正在运行的系统路径一致。

保留其他 provider 和 agent。主力默认模型为 `local-bonsai/bonsai-main`，支持
low / medium / high variants；`aggressive` 使用 `local-bonsai/bonsai-hikari`。

```sh
opencode run --model local-bonsai/bonsai-main --variant low '用中文解释二分查找。'
opencode run --agent aggressive '简要说明如何分析自己的开源程序。'
sudo systemctl status llama-swap bonsai-tailnet-gateway
sudo journalctl -u llama-swap -f
sudo systemctl stop bonsai-tailnet-gateway llama-swap
sudo systemctl start llama-swap bonsai-tailnet-gateway
```

模型由请求按需加载，两个 Podman 单元的 `autoStart` 均为 false。

## 恢复方式与保留文件

本次部署前的系统已经用 GC root 保留。恢复到核显与 CDI 配置完成、NInfer 尚未启用的系统：

```sh
sudo nix-env --profile /nix/var/nix/profiles/system --set /nix/store/x7h705zazxbmn2lpzc296kx5xvp4qvzp-nixos-system-seraph-26.05.20260911.21a67dc
sudo /nix/store/x7h705zazxbmn2lpzc296kx5xvp4qvzp-nixos-system-seraph-26.05.20260911.21a67dc/bin/switch-to-configuration switch
```

只关闭网络访问：使用文件编辑工具将 seraph 主机入口中的
`services.bonsaiNinfer.tailnet.enable` 改为 false，运行 `just check`、
`nixos-rebuild build --flake .#seraph`，然后执行需要 sudo 的 switch。

关闭 Bonsai 服务：同样将 `services.bonsaiNinfer.enable` 改为 false。
恢复 Home Manager 的默认模型时，使用文件编辑工具移除该主机的
`home/modules/opencode/local-bonsai.nix` 导入，运行 `just hm-dry` 和 `just hm`。
原有 provider 配置一直保留。seraph 激活前的 Home Manager generation 为：
`/nix/store/39ja9v9irjhf7f605b57ipyss6kvy19q-home-manager-generation`，可运行其 `activate`。

aegis 激活前的 Home Manager generation 为
`/nix/store/l109wzsmn4qr00ql5n4xwkw7gfs3xa70-home-manager-generation`，
恢复本地用户配置可运行该目录中的 `activate`。配置备份位于
`~/.config/nix-config/.work/ninfer-sync-20261005/`，包含激活前配置、主仓库归档与验证记录。

当前 NInfer 的 GGUF 转换输入、v2 模板、`.ninfer` 产物和 OCI 归档均保留。

## 旧版文件清理

按照用户的清理指令，已删除旧版 `feat/seraph-bonsai` 本地与远端分支、
专用工作目录、旧版下载资料包，以及服务器的 `/var/lib/llm-models/bonsai2/`。
旧版配置源文件已经从当前配置移除。

服务器第 6 至 12 代系统记录已删除，启动菜单已刷新。通过 Nix 引用检查回收
150 个失效 store 路径，释放约 1.3 GiB；PrismML llama.cpp 引擎路径已不存在。
包括旧 GGUF 和工作目录在内，服务器可用空间增加 16702251008 字节，约 15.6 GiB。
第 5、13、14、15 代系统记录保留，第 15 代继续运行。

清理前后的显卡模块 SHA256 完全一致，当前系统路径保持一致。
`llama-swap` 和 Tailscale 网关均运行正常；清理后两个模型的中文问答与真实工具调用
往返共 4 组检查全部通过。清理记录与复测响应包含在资料包的 `evidence/cleanup/` 中。

完整测量说明位于 `docs/incidents.md#seraph-bonsai-ninfer-174080`，
方案决定位于 `docs/decisions.md#seraph-bonsai-ninfer`。
