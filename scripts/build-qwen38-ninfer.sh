#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 NEW_BUILD_DIRECTORY [NEW_IMAGE_ARCHIVE]" >&2
  exit 2
fi

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="$1"
engine="${CONTAINER_ENGINE:-podman}"
revision="550d0ac3a50cc725c3a1618784a62287ea9df73b"
vision_patch="$repo_dir/nixos/hosts/wsl/ninfer-24g-vision-budget.patch"
catalog_patch="$repo_dir/nixos/modules/qwen38-ninfer-catalog-admission.patch"
patch_id="$(cat "$vision_patch" "$catalog_patch" | git hash-object --stdin)"
image="localhost/ninfer:qwen38-24g-550d0ac-${patch_id:0:12}"
builder="${image}-build"
# The host resolver can be loopback-only; use it from the build namespace too.
build_options=(--network=host)
if [[ -n "${NINFER_BUILD_MEMORY:-}" ]]; then
  build_options+=(--memory="$NINFER_BUILD_MEMORY" --memory-swap="$NINFER_BUILD_MEMORY")
fi

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
git -C "$build_dir" apply --check "$vision_patch"
git -C "$build_dir" apply "$vision_patch"
git -C "$build_dir" apply --check "$catalog_patch"
git -C "$build_dir" apply "$catalog_patch"

"$engine" build "${build_options[@]}" --target build --tag "$builder" "$build_dir"
"$engine" run --rm --network=none --entrypoint bash "$builder" -euc '
  g++ -std=c++20 -O2 -pthread -DNVTX_DISABLE \
    -I/usr/local/cuda/include -Iinclude -Isrc -Ithird_party \
    tests/test_resource_manager.cpp \
    src/runtime/engine/context_cost.cpp src/runtime/engine/context_cost_defaults.cpp \
    -o /tmp/ninfer-resource-manager-test
  /tmp/ninfer-resource-manager-test
'
"$engine" build "${build_options[@]}" --tag "$image" "$build_dir"
if [[ $# -eq 2 ]]; then
  "$engine" save --output "$2" "$image"
fi
echo "Validated image: $image"
