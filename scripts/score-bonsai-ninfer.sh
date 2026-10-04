#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 STATE_DIRECTORY MODEL ENGINE_SOURCE" >&2
  exit 2
fi
state_dir="$(realpath "$1")"
model="$2"
source_dir="$(realpath "$3")"
case "$model" in
  main) revision=e25d197aa62ce0a2 ;;
  hikari) revision=e7f6daf95ab820ef ;;
  *) echo "Unknown model: $model" >&2; exit 2 ;;
esac
corpus="$source_dir/eval/corpora/perplexity-1m/data/ninfer/00.txt"
sha256sum "$corpus"

for dtype in nvfp4 bf16; do
  output="$state_dir/logs/ppl-$model-32k-$dtype"
  test ! -e "$output"
  mkdir -p "$output"
  podman run --rm --network=none --ipc=host --device=nvidia.com/gpu=all \
    --volume "$state_dir/models:/models:ro" \
    --volume "$corpus:/eval/code.txt:ro" \
    --volume "$output:/results:rw" \
    localhost/ninfer:bonsai-9c875f71-sm120a \
    ninfer-perplexity "/models/bonsai-$model-$revision.ninfer" \
    --text /eval/code.txt --context 32768 --stride 16384 \
    --kv-dtype "$dtype" --output /results
done
