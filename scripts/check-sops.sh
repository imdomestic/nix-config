#!/usr/bin/env bash
# 校验每台主机 sops.secrets 里声明的键，在它对应的 sops 文件里真的存在。
#
# 这类不一致只在部署时才炸(sops-install-secrets 报 "the key ... cannot be found")，
# 而且报错发生在激活阶段，往往已经把服务重启了一半。放在这里可以提前发现。
#
# 注意每个 secret 可以有自己的 sopsFile —— 共享凭据(比如
# secrets/clients/imdomestic.yaml，六台 portal 的客户端凭据，mihomo 和
# singbox 两个模块共用)就不在 secrets/hosts/<host>.yaml 里。早期版本只查
# 后者，于是把所有走共享文件的键全报成缺失。误报比不报更糟：真出问题时
# 没人会再认真看它。现在按 (sopsFile, key) 分组，各查各的文件。
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
  # sops-nix 的 key 默认等于 secret 名，路径用 / 分层；sopsFile 逐个 secret 可覆盖
  declared=$(nix eval --json ".#nixosConfigurations.$h.config.sops.secrets" \
    --apply 'ss: builtins.attrValues (builtins.mapAttrs (_: v: { inherit (v) key; file = toString v.sopsFile; }) ss)' 2>/dev/null)
  if [ -z "$declared" ]; then
    printf '%-10s — 无法求值(可能没有 sops 配置)，跳过\n' "$h"
    continue
  fi

  # sopsFile 求值出来是 nix store 路径(/nix/store/<hash>-source/secrets/...)，
  # 而我们要核对的是工作树里的文件 —— store 里那份是上次 commit 的快照，
  # 未提交的改动查不到。剥掉 store 前缀换成仓库相对路径。
  declared=$(printf '%s' "$declared" | python3 -c '
import json,sys,re
es=json.load(sys.stdin)
for e in es:
    e["file"]=re.sub(r"^/nix/store/[^/]+/", "", e["file"])
json.dump(es,sys.stdout)')

  # 按 sopsFile 分组，逐个文件解密后核对
  files=$(printf '%s' "$declared" | python3 -c \
    'import json,sys; print("\n".join(sorted({e["file"] for e in json.load(sys.stdin)})))')
  [ -z "$files" ] && { printf '%-10s — 没有声明任何 secret\n' "$h"; continue; }

  total=0; missing_all=""
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if [ ! -f "$f" ]; then
      missing_all+="             (文件不存在) $f"$'\n'
      rc=1
      continue
    fi
    out=$(sops -d --output-type json "$f" 2>/dev/null | python3 -c '
import json, sys
data = json.load(sys.stdin)
entries = [e for e in json.loads(sys.argv[2]) if e["file"] == sys.argv[1]]
missing = []
for e in entries:
    node = data
    for part in e["key"].split("/"):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            missing.append(e["key"]); break
print(len(entries))
for m in missing: print("MISSING " + m)
' "$f" "$declared")
    n=$(printf '%s' "$out" | head -1)
    total=$((total + ${n:-0}))
    while IFS= read -r line; do
      case "$line" in
        MISSING\ *) missing_all+="             ${line#MISSING } (期望在 $f)"$'\n'; rc=1 ;;
      esac
    done <<<"$out"
  done <<<"$files"

  nfiles=$(printf '%s\n' "$files" | grep -c .)
  if [ -n "$missing_all" ]; then
    printf '%-10s ✗ 有键找不到:\n' "$h"
    printf '%s' "$missing_all"
  else
    printf '%-10s ✓ %d 个键 / %d 个 sops 文件\n' "$h" "$total" "$nfiles"
  fi
done

exit $rc
