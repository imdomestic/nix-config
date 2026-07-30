#!/usr/bin/env bash
# 把每台主机生成的 sing-box 配置交给 `sing-box check` 验一遍。
#
# 和 check-xray 同样的动机:`nix eval` 只保证 Nix 语法对,生成的 JSON 再离谱也
# 能求值通过。sing-box 1.13 尤其不能光靠肉眼——它把好几个「已弃用但还没删」的
# 写法直接做成了启动即 Fatal(旧式 DNS server、缺 default_domain_resolver、
# 1.10 的 inet4_address),配置看着完全正常,服务就是起不来。路由器上起不来
# 等于全家断网。
#
# 校验必须在目标主机上跑:auto_redirect / tun 是 Linux only,在 macOS 上
# `sing-box check` 会停在 "initialize auto-redirect: invalid argument",
# 那是平台差异不是配置错误,本地跑只会得到假阳性。check 只读文件,不碰正在跑
# 的服务,所以部署前跑是安全的。
#
# settings 里的 {"_secret": "/run/secrets/..."} 会被换成结构合法的假值,
# 所以不需要解密权限。
set -uo pipefail
cd "$(dirname "$0")/.."

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

hosts=("$@")
if [ ${#hosts[@]} -eq 0 ]; then
  for d in nixos/hosts/*/; do
    h=$(basename "$d")
    grep -Eqs '^[[:space:]]*\.\./\.\./modules/singbox' "$d"/*.nix && hosts+=("$h")
  done
fi
[ ${#hosts[@]} -eq 0 ] && { echo "没有主机启用 sing-box"; exit 0; }

rc=0
for h in "${hosts[@]}"; do
  raw=$(nix eval --json ".#nixosConfigurations.$h.config.services.sing-box.settings" 2>/dev/null)
  if [ -z "$raw" ] || [ "$raw" = "{}" ]; then
    printf '%-10s — 没有 sing-box 配置，跳过\n' "$h"
    continue
  fi

  printf '%s' "$raw" | python3 -c '
import json, sys, uuid

# 结构合法的假值:REALITY 会校验 UUID 格式、公钥长度(x25519, 43 字符
# base64url)和 short_id(偶数位十六进制)，随便填会误报。
FAKE = {
    "uuid":       lambda: str(uuid.uuid4()),
    "public_key": lambda: "zSIp8O0LSnJVLsv135KHBPjEA4To_1RzirwOVKowYSA",
    "short_id":   lambda: "a1b2c3d4",
    "password":   lambda: "zSIp8O0LSnJVLsv135KHBPjEA4To_1RzirwOVKowYSA",
}

def fill(node, key=None):
    if isinstance(node, dict):
        # NixOS sing-box 模块的密钥占位形式:{"_secret": "<路径>"}
        if set(node) == {"_secret"}:
            return FAKE.get(key, lambda: "a1b2c3d4")()
        return {k: fill(v, k) for k, v in node.items()}
    if isinstance(node, list):
        return [fill(v, key) for v in node]
    return node

json.dump(fill(json.load(sys.stdin)), open(sys.argv[1], "w"))
' "$work/$h.json" || { printf '%-10s ✗ 配置不是合法 JSON\n' "$h"; rc=1; continue; }

  # sing-box 本体和 .srs 规则集都得先在目标机上落地——它们是 store 路径，
  # 目标机没有的话 check 会报 "no such file or directory"，那是假阴性。
  paths=$(nix eval --raw ".#nixosConfigurations.$h.pkgs.sing-box.outPath" 2>/dev/null)
  for p in sing-geosite sing-geoip; do
    paths+=" $(nix eval --raw ".#nixosConfigurations.$h.pkgs.$p.outPath" 2>/dev/null)"
  done
  sb=${paths%% *}

  if ! scp -q "$work/$h.json" "$h:/tmp/sb-check-$h.json" 2>/dev/null; then
    printf '%-10s — 连不上，跳过（校验必须在目标机上跑）\n' "$h"
    continue
  fi
  out=$(ssh "$h" "nix-store --realise $paths >/dev/null 2>&1; $sb/bin/sing-box check -c /tmp/sb-check-$h.json 2>&1; rm -f /tmp/sb-check-$h.json" 2>&1)

  if [ -z "$out" ]; then
    read -r nin nout < <(python3 -c '
import json,sys
c=json.load(open(sys.argv[1]))
print(len(c.get("inbounds",[])), len(c.get("outbounds",[])))' "$work/$h.json")
    printf '%-10s ✓ %s 个 inbound / %s 个 outbound\n' "$h" "$nin" "$nout"
  else
    rc=1
    printf '%-10s ✗\n' "$h"
    sed 's/^/             /' <<<"$out" | tail -5
  fi
done
exit $rc
