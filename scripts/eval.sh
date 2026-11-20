#!/usr/bin/env bash
# 求值每台主机的系统和每个 home 到 drvPath，一个目标一个 nix 进程，几个并行。
#
# 为什么不用 `nix flake check`：放在一个进程里，求过的配置一直可达，Boehm GC
# 每轮都要把整个活堆重新标记一遍，总时间随配置数超线性增长——分开约 4 分钟 CPU
# 的量，合在一起 25 分钟还没完（docs/incidents.md#flake-check-gc-thrash）。
#
# 用法: scripts/eval.sh [host...]   不给参数就是全部；给了就只求这些主机的系统和 home。
# 环境: EVAL_JOBS 并发数(默认 4)，EVAL_SUBSTITUTERS 传给 --option substituters。
set -euo pipefail
cd "$(dirname "$0")/.."

jobs=${EVAL_JOBS:-4}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

names() {
  nix eval --raw ".#$1" --apply 'xs: builtins.concatStringsSep "\n" (builtins.attrNames xs)' 2>/dev/null
}

wanted() {
  [ "$#" -eq 1 ] && return 0
  local h=$1 f
  shift
  for f in "$@"; do [ "$f" = "$h" ] && return 0; done
  return 1
}

targets=()
for h in $(names nixosConfigurations); do
  if wanted "$h" "$@"; then targets+=("nixosConfigurations.$h.config.system.build.toplevel.drvPath"); fi
done
for h in $(names darwinConfigurations); do
  if wanted "$h" "$@"; then targets+=("darwinConfigurations.$h.config.system.build.toplevel.drvPath"); fi
done
for n in $(names homeConfigurations | grep '^hosts/'); do
  h=${n#hosts/}
  h=${h%%/*}
  if wanted "$h" "$@"; then targets+=("homeConfigurations.\"$n\".activationPackage.drvPath"); fi
done
[ "${#targets[@]}" -gt 0 ] || {
  echo "no targets for: $*" >&2
  exit 1
}

run_one() {
  local attr=$1 label id t0
  case $attr in
    nixosConfigurations.*) label=nixos/${attr#nixosConfigurations.} ;;
    darwinConfigurations.*) label=darwin/${attr#darwinConfigurations.} ;;
    *) label=home/${attr#homeConfigurations.} ;;
  esac
  label=${label%%.config.*}
  label=${label%%.activationPackage.*}
  label=${label//\"/}
  id=${label//\//_}
  t0=$SECONDS
  local opts=(--option eval-cores 1)
  [ -n "${EVAL_SUBSTITUTERS:-}" ] && opts+=(--option substituters "$EVAL_SUBSTITUTERS")
  if nice -n 10 nix eval --raw "${opts[@]}" ".#$attr" >/dev/null 2>"$EVAL_TMP/$id.err"; then
    printf 'ok    %4ds  %s\n' $((SECONDS - t0)) "$label"
  else
    printf 'FAIL  %4ds  %s\n' $((SECONDS - t0)) "$label"
    printf '%s\n' "$attr" >"$EVAL_TMP/$id.fail"
  fi
}
export -f run_one
export EVAL_TMP=$tmp EVAL_SUBSTITUTERS=${EVAL_SUBSTITUTERS:-}

echo "evaluating ${#targets[@]} targets, $jobs at a time"
start=$SECONDS
printf '%s\0' "${targets[@]}" | xargs -0 -n1 -P "$jobs" bash -c 'run_one "$1"' _

failed=0
for f in "$tmp"/*.fail; do
  [ -e "$f" ] || continue
  failed=$((failed + 1))
  attr=$(cat "$f")
  echo
  echo "── $(basename "$f" .fail)   nix eval --show-trace --raw '.#$attr'"
  grep -vE '^(evaluation )?warning:' "${f%.fail}.err" | tail -n 15 || true
done
echo
echo "$((${#targets[@]} - failed))/${#targets[@]} evaluated in $((SECONDS - start))s"
[ "$failed" -eq 0 ]
