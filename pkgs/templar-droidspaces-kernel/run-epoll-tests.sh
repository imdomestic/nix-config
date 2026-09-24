#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 4 ]]; then
  echo "usage: $0 QEMU_SYSTEM_AARCH64 KERNEL_IMAGE INITRD LOG_FILE" >&2
  exit 2
fi

timeout 180 "$1" \
  -machine virt,gic-version=3 -cpu cortex-a57 -accel tcg \
  -smp 2 -m 2048 -nographic -no-reboot -nic none \
  -kernel "$2" -initrd "$3" \
  -append 'console=ttyAMA0 earlycon rdinit=/init panic=-1 nokaslr' \
  >"$4" 2>&1

grep 'EPOLL_PWAIT2_TESTS_PASSED' "$4"
if grep -Eq 'FAIL \[|EPOLL_PWAIT2_TESTS_FAILED|Kernel panic' "$4"; then
  exit 1
fi
grep -c '^PASS ' "$4"
