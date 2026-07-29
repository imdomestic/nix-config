#!/usr/bin/env bash
# 校验每台主机 sops.secrets 里声明的键，在它的 secrets/hosts/<host>.yaml 里真的存在。
#
# 这类不一致只在部署时才炸(sops-install-secrets 报 "the key ... cannot be found")，
# 而且报错发生在激活阶段，往往已经把服务重启了一半。放在这里可以提前发现。
#
# 用法: check-sops.sh [host...]   不给参数就检查所有既有 sops 文件又有 nixos 配置的主机。
set -uo pipefail
cd "$(dirname "$0")/.."

hosts=("$@")
if [ ${#hosts[@]} -eq 0 ]; then
  for f in secrets/hosts/*.yaml; do
    h=$(basename "$f" .yaml)
    [ -d "nixos/hosts/$h" ] && hosts+=("$h")
  done
fi

rc=0
for h in "${hosts[@]}"; do
  f="secrets/hosts/$h.yaml"
  if [ ! -f "$f" ]; then
    printf '%-10s — 无 sops 文件，跳过\n' "$h"
    continue
  fi

  # sops-nix 的 key 默认等于 secret 名，路径用 / 分层
  declared=$(nix eval --json ".#nixosConfigurations.$h.config.sops.secrets" \
    --apply 'ss: builtins.attrValues (builtins.mapAttrs (_: v: v.key) ss)' 2>/dev/null)
  if [ -z "$declared" ]; then
    printf '%-10s ✗ 求值失败\n' "$h"
    rc=1
    continue
  fi

  if ! sops -d --output-type json "$f" 2>/dev/null |
    python3 -c '
import json, sys

data = json.load(sys.stdin)
host, keys = sys.argv[1], json.loads(sys.argv[2])

missing = []
for key in keys:
    node = data
    for part in key.split("/"):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            missing.append(key)
            break

if missing:
    print(f"{host:<10} ✗ {len(missing)}/{len(keys)} 个声明的键在文件里找不到:")
    for key in missing:
        print(f"             {key}")
    sys.exit(1)
print(f"{host:<10} ✓ {len(keys)} 个键")
' "$h" "$declared"; then
    rc=1
  fi
done

exit $rc
