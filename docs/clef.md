# Clef on Taipan

Clef 27B is a decision model. It reads a state and typed questions, and returns
choices, scores and probabilities. The deployment uses the official Ollama
Q4_K_M package on Taipan's RTX 5090 D v2 (24,455 MiB VRAM).

## API

The existing Tailnet gateway serves `POST http://taipan:8000/v1/systemone`.
Use model ID `clef-27b`. The backend is loopback-only; the gateway supplies the
same model switching as the two existing Qwen profiles.

```sh
curl --fail-with-body http://taipan:8000/v1/systemone \
  -H 'Content-Type: application/json' --data-binary @- <<'JSON'
{
  "model": "clef-27b",
  "state": "I was charged twice for the same order. Please refund the duplicate payment.",
  "questions": {
    "team": {
      "type": "choice",
      "instructions": "Which team should handle this ticket?",
      "criteria": {
        "billing": "Payments and refunds",
        "technical": "Software bugs"
      }
    },
    "refund": {
      "type": "noul",
      "instructions": "Does the customer request a refund?"
    }
  }
}
JSON
```

The initial profile is **4,096 input tokens and one concurrent request**.
The complete encoded state, questions, criteria and images must fit that
window. History is supplied as part of `state` when needed by the decision.

Clef and Qwen are in llama-swap's default exclusive group. Switching models
stops the previous container and releases its GPU allocation. A cold request
includes process startup and loading weights from disk. Do not start and use
the backend directly while another model is active.

## Configuration and storage

- Host: `nixos/hosts/taipan/system.nix` imports
  `nixos/modules/clef-ollama.nix`.
- Runtime: official Ollama 0.40.4 container, with NVIDIA CDI and host networking.
- Unit: `podman-clef.service`, started on demand by llama-swap.
- Persistent model directory: `/var/lib/clef-ollama`.
- Source model: `clef:27b-q4_K_M`; the local `clef-27b-4k` derivative shares
  its blobs and sets `num_ctx = 4096`.
- The upstream package sets `num_ctx = 16384`, which overrides the environment
  default. Setting only `OLLAMA_CONTEXT_LENGTH` does not establish the intended
  4K profile.
- `scripts/patches/llama-swap-systemone.patch` adds model dispatch for
  `/v1/systemone`; this uses the existing model-name rewrite, concurrency and
  switching pipeline.
- The outer gateway reads the merged `services.llama-swap.settings`, so a model
  added by another module also appears in its model metadata.

Initialization downloads the source model only if it is missing, then creates
the local derivative through Ollama's API. It does not refresh an existing
source tag on every start.

The readiness probe retrieves `/v1/models/clef-27b-4k`, ensuring that the local
model exists before routing requests. Startup and version findings are in
[the incident record](incidents.md#taipan-clef-decision-startup).

The 2026-10-15 upstream model blobs are:

| Asset | Bytes | SHA-256 |
| --- | ---: | --- |
| Model, including decision tensors | 19,232,219,200 | `bd9b8ae24c5752a2bb5e2733d5168340d5f04457e02b8bf0d1bc9285ec3d4f61` |
| Vision projector | 931,146,304 | `2a3e89934a6dbd7d4c53868cd810b89c50095dd324f846d62f4e8c779547e234` |

These are file sizes, with runtime allocations accounted for separately.
The source manifest SHA-256 is
`7885241a86db4803ff95b6a8fc60dc132a5f9612a76db786a304cfa8c760f84b`.
When preseeding blobs offline, install their complete manifest, config and
parameter blobs before starting Ollama, so the model is recognized and the
blobs are referenced during startup cleanup.

## Memory and validation

The main variables beyond weights are encoded input length, image token count,
question/option count, request concurrency, compute batch/chunk sizes,
activation precision, attention implementation, and backend buffer/cache
allocation. CUDA and the allocator also retain memory. Quantizing weights to
four bits does not make every intermediate tensor four bits.

The upstream PyTorch reference explicitly sets `use_cache=False`. Ollama
0.40.4's `LlamaServerBatch` also identifies models with `decision.block_count`
as whole-prompt decisions without a KV cache, and sets the physical batch size
to the effective context length. Its memory planner adds a conservative
2 GiB allowance at batch sizes of 2,048 and above; this is an estimate, not a
measurement. Startup buffers can therefore depend on the configured window
even for a short request. Verify allocations in startup logs and requests
instead of copying NInfer's KV settings.

The validation script tests cold/warm requests, a longer input, 32 questions,
image decisions, context overflow and recovery. With `--check-swap`, it also
switches to Qwen and back. GPU memory is sampled every 100 ms; sub-interval
peaks may be missed.

```sh
python3 scripts/test-clef-deployment.py \
  --check-swap --output /tmp/clef-validation.json
```

Measured memory, latency and acceptance results are in
[the 2026-10-15 incident record](incidents.md#taipan-clef-decision-startup).

Primary references:
[Cloudflare model and reference code](https://huggingface.co/Cloudflare/clef),
[Ollama package](https://ollama.com/library/clef:27b-q4_K_M),
[Ollama System One API](https://docs.ollama.com/api/systemone),
[Ollama batch and memory planning](https://github.com/ollama/ollama/blob/v0.40.4/llm/llama_server.go#L94),
[Ollama 0.40.4](https://github.com/ollama/ollama/releases/tag/v0.40.4).
