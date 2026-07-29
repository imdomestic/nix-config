#!/usr/bin/env bash
# 把每台主机生成的 xray 配置交给 xray -test 验一遍。
#
# `nix eval` 只保证 Nix 语法对，check-tunnels 只比对反代域名，两者都不会发现
# 「realitySettings 是空的」这类语义错误——那种配置能求值、能生成 JSON，直到
# xray 启动时才报 `empty "password"` 并让服务起不来。曾经因此把 r6s 打挂过。
#
# sops 占位符会被换成结构合法的假值(UUID/密钥/shortId)，所以不需要解密权限。
set -uo pipefail
cd "$(dirname "$0")/.."

XRAY=$(nix build --no-link --print-out-paths nixpkgs#xray 2>/dev/null)/bin/xray
[ -x "$XRAY" ] || { echo "拿不到 xray"; exit 1; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

hosts=("$@")
if [ ${#hosts[@]} -eq 0 ]; then
  for d in nixos/hosts/*/; do
    h=$(basename "$d")
    grep -rqs "services.xray" "$d" && hosts+=("$h")
  done
fi

rc=0
for h in "${hosts[@]}"; do
  raw=$(nix eval --raw ".#nixosConfigurations.$h.config.sops.templates.\"xray-config.json\".content" 2>/dev/null)
  [ -z "$raw" ] && raw=$(nix eval --json ".#nixosConfigurations.$h.config.services.xray.settings" 2>/dev/null)
  if [ -z "$raw" ]; then
    printf '%-10s — 没有 xray 配置，跳过\n' "$h"
    continue
  fi

  printf '%s' "$raw" | python3 -c '
import json, sys, uuid

# 结构合法的假值:REALITY 会校验密钥长度和 UUID 格式，随便填会误报
FAKE = {
    "id":         lambda: str(uuid.uuid4()),
    "privateKey": lambda: "SFu6PPiYyTwMoz8SRbugUZdgYqNdXpwOaVtTWGidOX0",
    "publicKey":  lambda: "zSIp8O0LSnJVLsv135KHBPjEA4To_1RzirwOVKowYSA",
    "password":   lambda: "SFu6PPiYyTwMoz8SRbugUZdgYqNdXpwOaVtTWGidOX0",
}

def fill(node, key=None):
    if isinstance(node, dict):
        return {k: fill(v, k) for k, v in node.items()}
    if isinstance(node, list):
        return [fill(v, key) for v in node]
    if isinstance(node, str) and node.startswith("<SOPS:"):
        return FAKE.get(key, lambda: "a1b2c3d4")()
    return node

json.dump(fill(json.load(sys.stdin)), open(sys.argv[1], "w"))
' "$work/$h.json" || { printf '%-10s ✗ 配置不是合法 JSON\n' "$h"; rc=1; continue; }

  out=$("$XRAY" -test -config "$work/$h.json" 2>&1)
  if grep -q "Configuration OK" <<<"$out"; then
    n=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("inbounds",[])))' "$work/$h.json")
    printf '%-10s ✓ %d 个 inbound\n' "$h" "$n"
  else
    rc=1
    printf '%-10s ✗\n' "$h"
    grep -vE "^$|\[Warning\]" <<<"$out" | tail -3 | sed 's/^/             /'
  fi
done
exit $rc
