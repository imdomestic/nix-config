#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 STATE_DIRECTORY ENGINE_SOURCE" >&2
  exit 2
fi
state_dir="$(realpath "$1")"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export ZATFUNG_ROOT="$(realpath "$2")"
export ZATFUNG_TEMPLATE="$state_dir/inputs/qwen3_8_27b-v2-dc370fb6295a.ninfer"
export OMP_NUM_THREADS=6
export OPENBLAS_NUM_THREADS=6
export TMPDIR="${TMPDIR:?Set TMPDIR to a writable directory on disk}"
test "$(git -C "$ZATFUNG_ROOT" rev-parse HEAD)" = 9c875f710c459768468d74632e796d782a7e98fc
python3.11 -c 'import sys, numpy, torch; assert sys.version_info[:2] == (3, 11); assert torch.version.cuda is None; print(sys.version, numpy.__version__, torch.__version__)'
test "$(stat -c %s "$ZATFUNG_TEMPLATE")" = 20437336576
mkdir -p "$state_dir/models" "$state_dir/logs"

convert_model() {
  local model="$1" gguf="$2" revision="$3" sha="$4"
  export ZATFUNG_GGUF="$state_dir/inputs/$gguf"
  local output="$state_dir/models/$model-$revision.ninfer"
  test "$(stat -c %s "$ZATFUNG_GGUF")" = 7206168928
  printf '%s  %s\n' "$sha" "$ZATFUNG_GGUF" | sha256sum --check
  if [[ -e "$output" || -e "$output.part" ]]; then
    echo "Output already exists: $output" >&2
    exit 1
  fi
  python3.11 -u "$ZATFUNG_ROOT/tools/ternary-convert/pack_zatfung.py" check \
    | tee "$state_dir/logs/$model-check.log"
  python3.11 -u "$ZATFUNG_ROOT/tools/ternary-convert/pack_zatfung.py" build "$output.part" \
    | tee "$state_dir/logs/$model-build.log"
  mv "$output.part" "$output"
  sha256sum "$output" | tee "$output.sha256"
  stat -c '%n %s bytes' "$output"
}

convert_model bonsai-main Ternary-Bonsai-2-27B-Abliterated-v2-PQ2_0.gguf e25d197aa62ce0a2 \
  b284cbc6cb6c2894eb3d4181d805b966948128b2add9627dbd7d1e691724b3bb
convert_model bonsai-hikari Ternary-Bonsai-2-27B-Abliterated-PQ2_0.gguf e7f6daf95ab820ef \
  41a362f422b70a8c2dc74a3cc14447ad0ea702c440f0dbe41dc1796da7b7e342
python3.11 "$script_dir/audit-bonsai-artifacts.py" "$state_dir"
