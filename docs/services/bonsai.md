# Bonsai on seraph

seraph 的 RTX 5070 用 NInfer 跑两个 Ternary Bonsai 2 27B 模型，经 llama-swap 按需加载、
互斥占卡（同一时间只装一个）。

- 系统模块：`system/modules/bonsai-ninfer.nix`；远程入口：`system/modules/bonsai-tailnet.nix`；
  转换环境：`system/modules/bonsai-conversion.nix`。
- 模型参数与校验值：`lib/bonsai-models.nix`。
- 方案为什么是 NInfer：`docs/decisions.md#seraph-bonsai-ninfer`；
  174080 上下文的构建、转换与实测：`docs/incidents.md#seraph-bonsai-ninfer-174080`。

## 访问

`http://seraph.inner.imdomestic.com:8080/v1`，需要 Bonsai API key（SOPS 提供运行时 key，
缺失或错误都返回 401）。网关只绑定 seraph 的 Tailscale IPv4，防火墙限定 tailnet 接口；
凡是 tailnet 策略允许访问 seraph 的设备都能连，不另设设备 IP 白名单。不对 LAN 或公网开放。

| 模型 ID | 输入 | 推理强度 |
| --- | --- | --- |
| `bonsai-main` | `BoldingBuilds/Ternary-Bonsai-2-27B-Abliterated-v2-PQ2_0-MTP-GGUF` @ `e25d197a` | 默认 high（API 的 high 映射到引擎的 xhigh），可选 low / medium |
| `bonsai-hikari` | `Hikari07jp/Ternary-Bonsai-2-27B-Abliterated-GGUF` @ `e7f6daf9` | 锁定 medium |

linwhite 的 OpenCode 通过 `home/linwhite/modules/opencode/local-bonsai.nix` 使用它们：
默认 `local-bonsai/bonsai-main`，`aggressive` agent 用 `bonsai-hikari`。

```sh
opencode run --model local-bonsai/bonsai-main --variant low '用中文解释二分查找。'
sudo systemctl status llama-swap bonsai-tailnet-gateway
sudo journalctl -u llama-swap -f
```

两个 Podman 单元 `autoStart = false`，由请求触发加载；llama-swap 的加载健康检查超时 120 秒。

## 服务参数

两个模型相同：

```text
--max-context 174080 --kv-capacity 174080 --kv-dtype nvfp4
--spec mtp --draft-tokens 3 --max-concurrency 1
--prefill-chunk 1024 --preserve-thinking --default-max-tokens 16384
--max-pending-requests 16 --pending-timeout-ms 600000
```

输入和输出共用 174080 的上下文，16384 是输出上限。不开 KVMem；活动请求的 KV 全在 GPU 上，
NInfer 默认的主机前缀缓存保留。

| 显存（K=3） | 字节 |
| --- | ---: |
| GPU 权重 | 7641154560 |
| runtime（含 KV） | 4017176832 |
| 其中 KV payload | 3409256448 |
| 启动后 CUDA 剩余 | 565248000 |

165000 token 的长输入实测峰值 11238 MiB、最少剩 538 MiB，预填充约 168 秒。
MTP K=3 比 K=5 快（主力 128.1 对 119.2 tok/s，Hikari 126.3 对 123.9 tok/s），所以固定 K=3。
32k 真实代码语料上 NVFP4 KV 相对 BF16 的 PPL 偏差：主力 +0.234%，Hikari +0.165%。

## 补丁

- `bonsai-ninfer-high-alias.patch`：引擎原生只有 low / medium / xhigh，把 API 的 high 映射到 xhigh。
- llama-swap v224 的 `setParams` 会覆盖客户端的值；补丁加了 `setParamsIfAbsent` 和 `byPath`，
  分别处理 Chat 的 `reasoning_effort` 和 Responses 的 `reasoning.effort`，并加入 Responses
  的 token 计数路由。Hikari 的 medium 锁定在 Chat、Responses、upstream 三个入口都生效。

## 构建与产物

| 项目 | 值 |
| --- | --- |
| NInfer | `CraneBW/ninfer-ternary-bonsai-ada` @ `9c875f710c459768468d74632e796d782a7e98fc` |
| 编译 | `sm_120a`，CUDA 13.1.2 容器，595.71.05 开放内核驱动 |
| 模板 | Qwen3.8-27B v2，HF revision `dc370fb6295a` |
| 转换环境 | Nix 声明的 Python 3.11、NumPy 2.3.4、CPU Torch 2.11.0 |
| 镜像 | `localhost/ninfer:bonsai-9c875f71-sm120a-high` |

两份 GGUF 都是 7206168928 字节、851 个张量，转换产物在 `/var/lib/bonsai-ninfer/models/`
（各 10533732876 字节，SHA-256 见 `lib/bonsai-models.nix`）。MTP、frontend、draft_head 等
模板对象从模板借用，逐个核对过 SHA-256。完整 embedding 解码检查需要的内存超过物理内存，
所以配置里声明了 64 GiB 的磁盘交换文件。

## 停用

- 只关远程入口：`services.bonsaiNinfer.tailnet.enable = false`（`hosts/seraph/host.nix`）。
- 关整个服务：`services.bonsaiNinfer.enable = false`。
- linwhite 的 OpenCode 回到原默认：去掉该主机对 `local-bonsai.nix` 的导入，再 `just hm`。
