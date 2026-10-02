#!/usr/bin/env bash
set -euo pipefail

model_dir="${1:-/var/lib/qwen38/ninfer-models}"
revision="d52441e7706846f325f0d2d419c93b632b3bdc1a"
sha256="65f9d2ab1161e95d65ecdb20858b42ae937bb40c92d3dabf969fd47bfd03c0cb"
filename="qwen3_8_27b_swift15abl_nvfp4full-dflash2-d52441e7.ninfer"
url="https://huggingface.co/kaushikvira/Qwen3.8-27B-swift15-uncensored-ajgazin-nvfp4full-dflash2-NInfer-v3/resolve/$revision/qwen3_8_27b_swift15abl_nvfp4full-dflash2.ninfer"

mkdir -p "$model_dir"
if [[ -f "$model_dir/$filename" ]]; then
  printf '%s  %s\n' "$sha256" "$model_dir/$filename" | sha256sum --check
  exit 0
fi
if command -v aria2c >/dev/null; then
  aria2c --continue=true --max-connection-per-server=16 --split=16 \
    --min-split-size=64M --file-allocation=none --enable-color=false \
    --show-console-readout=false --summary-interval=30 --console-log-level=warn \
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
