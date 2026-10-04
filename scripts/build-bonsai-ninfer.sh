#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 BUILD_DIRECTORY IMAGE_ARCHIVE" >&2
  exit 2
fi

build_dir="$1"
archive="$2"
revision="9c875f710c459768468d74632e796d782a7e98fc"
image="localhost/ninfer:bonsai-9c875f71-sm120a-high"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
patch_files=(
  "$script_dir/patches/bonsai-ninfer-sm120a.patch"
  "$script_dir/patches/bonsai-ninfer-high-alias.patch"
)
jobs="${NINFER_BUILD_JOBS:-6}"
memory="${NINFER_BUILD_MEMORY:-24g}"
export TMPDIR="${TMPDIR:?Set TMPDIR to a writable directory on disk}"
mkdir -p "$TMPDIR"
test "$(stat -f -c %T "$TMPDIR")" != tmpfs

if [[ -e "$archive" ]]; then
  echo "Archive already exists: $archive" >&2
  exit 1
fi
if [[ ! -e "$build_dir" ]]; then
  git clone --filter=blob:none --no-checkout https://github.com/CraneBW/ninfer-ternary-bonsai-ada.git "$build_dir"
  git -C "$build_dir" checkout --detach "$revision"
  for patch_file in "${patch_files[@]}"; do
    git -C "$build_dir" apply --check "$patch_file"
    git -C "$build_dir" apply "$patch_file"
  done
else
  test "$(git -C "$build_dir" rev-parse HEAD)" = "$revision"
  for patch_file in "${patch_files[@]}"; do
    git -C "$build_dir" apply --reverse --check "$patch_file"
  done
fi

podman build --network=host --memory="$memory" --memory-swap="$memory" \
  --build-arg "NINFER_BUILD_JOBS=$jobs" --volume "$TMPDIR:/build-tmp:rw" \
  --tag "$image" "$build_dir"
podman run --rm --network=none --device=nvidia.com/gpu=all "$image" ninfer-serve --help
podman run --rm --network=none --device=nvidia.com/gpu=all "$image" ninfer-perplexity --help
mkdir -p "$(dirname -- "$archive")"
podman save --format oci-archive --output "$archive" "$image"
sha256sum "$archive"
echo "Built image: $image"
