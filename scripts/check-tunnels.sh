#!/usr/bin/env bash
# 交叉核对 xray 反向代理两端的域名：r5sjp 是 bridge 端，其余是 portal 端，
# 两边注册的 `reverse-*.hank.internal` 必须一字不差，否则隧道建不起来。
#
# 这种不匹配不会有任何报错——xray 两端都正常启动、端口照常监听、Reality
# 回落也正常，只是流量到了 portal 就无处可去。曾经因为主机目录名(shanghai)
# 和隧道短名(sh)不一致而踩过。
#
# 纯求值，不需要能解密 sops。
set -uo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import json
import subprocess
import sys

BRIDGE_HOST = "r5sjp"


def xray_config(host):
    """主机可能用 settings(内联) 或 settingsFile(sops 模板渲染)，两种都取。"""
    for attr in (
        f'config.sops.templates."xray-config.json".content',
        "config.services.xray.settings",
    ):
        args = ["nix", "eval", f".#nixosConfigurations.{host}.{attr}"]
        args += ["--raw"] if "templates" in attr else ["--json"]
        p = subprocess.run(args, capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            try:
                return json.loads(p.stdout)
            except json.JSONDecodeError:
                pass
    return None


bridge_cfg = xray_config(BRIDGE_HOST)
if not bridge_cfg:
    sys.exit(f"读不到 {BRIDGE_HOST} 的 xray 配置")

bridges = {
    b["tag"].removeprefix("bridge-"): b["domain"]
    for b in bridge_cfg.get("reverse", {}).get("bridges", [])
}

# 隧道短名不一定等于主机目录名，所以按 portal tag 反查
portals = {}
for host in sorted(p.name for p in __import__("pathlib").Path("nixos/hosts").iterdir()):
    if host == BRIDGE_HOST:
        continue
    cfg = xray_config(host)
    for portal in (cfg or {}).get("reverse", {}).get("portals", []):
        portals[portal["tag"].removeprefix("portal-")] = (host, portal["domain"])

rc = 0
for short, bridge_domain in sorted(bridges.items()):
    if short not in portals:
        print(f"  {short:5s} ⚠ bridge 指向它，但没有主机声明对应的 portal")
        continue
    host, portal_domain = portals[short]
    if portal_domain == bridge_domain:
        print(f"  {short:5s} ✓ {host}")
    else:
        rc = 1
        print(f"  {short:5s} ✗ {host}")
        print(f"          bridge({BRIDGE_HOST}) = {bridge_domain}")
        print(f"          portal({host})      = {portal_domain}")

for short, (host, _) in sorted(portals.items()):
    if short not in bridges:
        print(f"  {short:5s} ⚠ {host} 声明了 portal，但 {BRIDGE_HOST} 没有对应 bridge")

sys.exit(rc)
PY
