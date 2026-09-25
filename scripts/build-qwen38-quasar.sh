#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 NEW_BUILD_DIRECTORY [NEW_IMAGE_ARCHIVE]" >&2
  exit 2
fi

build_dir="$1"
engine="${CONTAINER_ENGINE:-podman}"
revision="bace20dc70249eed6402b66d4852c6c3f9612905"
image="localhost/ninfer:qwen38-quasar-bace20dc-vision48k"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
jobs="${NINFER_BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN)}"
memory="${NINFER_BUILD_MEMORY:-8g}"

if [[ -e "$build_dir" || -L "$build_dir" ]]; then
  echo "Build directory must be new: $build_dir" >&2
  exit 1
fi
if [[ $# -eq 2 && ( -e "$2" || -L "$2" ) ]]; then
  echo "Image archive must be new: $2" >&2
  exit 1
fi

git clone --filter=blob:none --no-checkout https://github.com/Neroued/ninfer.git "$build_dir"
git -C "$build_dir" checkout --detach "$revision"
# Keep single-item workspace unchanged: docs/incidents.md#b650-vision-total-48k.
git -C "$build_dir" apply "$script_dir/patches/qwen38-ninfer-vision48k.patch"
# Honor an explicit job override; otherwise use every available CPU thread.
sed -i "s/--parallel --target/--parallel $jobs --target/" "$build_dir/Dockerfile"
"$engine" build --network=host --memory="$memory" --memory-swap="$memory" \
  --tag "$image" "$build_dir"
"$engine" run --rm --network=none --device=nvidia.com/gpu=all "$image" ninfer-serve --help
if [[ $# -eq 2 ]]; then
  "$engine" save --output "$2" "$image"
fi
echo "Built image: $image"
