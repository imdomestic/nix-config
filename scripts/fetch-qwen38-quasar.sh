#!/usr/bin/env bash
set -euo pipefail

model_dir="${1:-/var/lib/qwen38/ninfer-models}"
revision="a45b9f5c0b374e0f31c20559ab8d25c92d627a8c"
sha256="8b86901a8cd2a297a3d737e470c793b67e5ce65b49131c48c2f2f0b346fd943c"
filename="qwen3_8_27b_nvfp4qat-a45b9f5c.ninfer"
url="https://huggingface.co/cometkim/Qwen3.8-27B-nvfp4qat-NInfer/resolve/$revision/qwen3_8_27b_nvfp4qat.ninfer"

mkdir -p "$model_dir"
if [[ -f "$model_dir/$filename" ]]; then
  printf '%s  %s\n' "$sha256" "$model_dir/$filename" | sha256sum --check
  exit 0
fi
if command -v aria2c >/dev/null; then
  aria2c --continue=true --max-connection-per-server=8 --split=8 \
    --min-split-size=64M --file-allocation=none --enable-color=false \
    --show-console-readout=false --summary-interval=30 \
    --dir="$model_dir" --out="$filename.part" "$url"
else
  if [[ -e "$model_dir/$filename.part.aria2" ]]; then
    echo "Install aria2c to resume this segmented download." >&2
    exit 1
  fi
  curl --fail --location --retry 5 --continue-at - \
    --output "$model_dir/$filename.part" "$url"
fi
printf '%s  %s\n' "$sha256" "$model_dir/$filename.part" | sha256sum --check
mv "$model_dir/$filename.part" "$model_dir/$filename"
