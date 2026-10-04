#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 STATE_DIRECTORY ENGINE_SOURCE" >&2
  exit 2
fi
state_dir="$(realpath -m "$1")"
source_dir="$(realpath "$2")"
revision="9c875f710c459768468d74632e796d782a7e98fc"
test "$(git -C "$source_dir" rev-parse HEAD)" = "$revision"
export TMPDIR="${TMPDIR:?Set TMPDIR to a writable directory on disk}"
export GOCACHE="$state_dir/go-cache"
mkdir -p "$state_dir/inputs" "$state_dir/tools" "$state_dir/logs" "$state_dir/models" "$TMPDIR"
test "$(stat -f -c %T "$TMPDIR")" != tmpfs

fetch_model() {
  local repo="$1" rev="$2" filename="$3" sha="$4" bytes="$5" reuse="$6"
  local destination="$state_dir/inputs/$filename"
  if [[ ! -f "$destination" ]]; then
    if [[ -f "$reuse" ]]; then
      cp --reflink=auto "$reuse" "$destination.part"
    else
      curl --fail --location --retry 12 --retry-connrefused --retry-delay 5 \
        --continue-at - --output "$destination.part" \
        "https://huggingface.co/$repo/resolve/$rev/$filename"
    fi
    test "$(stat -c %s "$destination.part")" = "$bytes"
    printf '%s  %s\n' "$sha" "$destination.part" | sha256sum --check
    mv "$destination.part" "$destination"
  fi
  test "$(stat -c %s "$destination")" = "$bytes"
  printf '%s  %s\n' "$sha" "$destination" | sha256sum --check
}

fetch_model \
  BoldingBuilds/Ternary-Bonsai-2-27B-Abliterated-v2-PQ2_0-MTP-GGUF \
  e25d197aa62ce0a2f685fc65d76a41b2416c5e66 \
  Ternary-Bonsai-2-27B-Abliterated-v2-PQ2_0.gguf \
  b284cbc6cb6c2894eb3d4181d805b966948128b2add9627dbd7d1e691724b3bb \
  7206168928 /var/lib/llm-models/bonsai2/Ternary-Bonsai-2-27B-Abliterated-v2-PQ2_0.gguf
fetch_model \
  Hikari07jp/Ternary-Bonsai-2-27B-Abliterated-GGUF \
  e7f6daf95ab820ef8de7d8f5e883d95d546ab02c \
  Ternary-Bonsai-2-27B-Abliterated-PQ2_0.gguf \
  41a362f422b70a8c2dc74a3cc14447ad0ea702c440f0dbe41dc1796da7b7e342 \
  7206168928 /var/lib/llm-models/bonsai2/Ternary-Bonsai-2-27B-Abliterated-PQ2_0.gguf

go build -o "$state_dir/tools/template-fetch" "$source_dir/tools/template-fetch/main.go"
"$state_dir/tools/template-fetch" -out "$state_dir/inputs/qwen3_8_27b-v2-dc370fb6295a.ninfer" -j 4
