#!/usr/bin/env python3
"""airport —— 查看用量、取订阅链接、重置配额。

只读的子命令直接看账本;会改状态的(reset)改完立刻触发一次调和,
免得改了配额还要等 timer 到点才生效。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import date, datetime
from typing import Any
from zoneinfo import ZoneInfo

GIB = 1024**3


def load(cfg_path: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    with open(cfg_path) as fh:
        cfg = json.load(fh)
    state_path = os.path.join(cfg["stateDir"], "state.json")
    try:
        with open(state_path) as fh:
            state = json.load(fh)
    except FileNotFoundError:
        state = {"users": {}}
    return cfg, state, state_path


def cmd_status(cfg: dict[str, Any], state: dict[str, Any], _: argparse.Namespace) -> int:
    users = state.get("users", {})
    today = datetime.now(ZoneInfo(cfg.get("timezone", "Asia/Shanghai"))).date()
    print(f"{'用户':<12} {'已用/配额':>20} {'到期':<12} {'剩余':>6}  状态")
    print("-" * 68)
    for name, user_cfg in sorted(cfg["users"].items()):
        entry = users.get(name, {})
        used = entry.get("up", 0) + entry.get("down", 0)
        quota = int(user_cfg.get("quotaGB", 0))
        expires = user_cfg.get("expires", "")
        left = (date.fromisoformat(expires) - today).days if expires else None
        usage = f"{used / GIB:.2f}/{quota} GiB" if quota else f"{used / GIB:.2f} GiB"
        if entry.get("active"):
            status = "正常"
        elif not entry:
            status = "尚未签发(跑一次 airport sync)"
        else:
            status = entry.get("reason") or "已停用"
        print(
            f"{name:<12} {usage:>20} {expires:<12} "
            f"{(str(left) + 'd') if left is not None else '-':>6}  {status}"
        )
    return 0


def cmd_show(cfg: dict[str, Any], state: dict[str, Any], args: argparse.Namespace) -> int:
    entry = state.get("users", {}).get(args.user)
    if not entry or not entry.get("token"):
        print(f"{args.user} 还没有凭据,先跑 airport sync", file=sys.stderr)
        return 1
    base = f"{cfg['subscription']['baseUrl']}/sub/{entry['token']}"
    print(f"通用 (v2rayN/NekoBox/Shadowrocket):\n  {base}")
    print(f"Clash / mihomo:\n  {base}/clash")
    print(f"sing-box:\n  {base}/singbox")
    return 0


def cmd_reset(cfg: dict[str, Any], state: dict[str, Any], args: argparse.Namespace) -> int:
    entry = state.get("users", {}).get(args.user)
    if entry is None:
        print(f"没有 {args.user} 这个用户", file=sys.stderr)
        return 1
    was = entry.get("up", 0) + entry.get("down", 0)
    entry["up"] = 0
    entry["down"] = 0
    state_path = os.path.join(cfg["stateDir"], "state.json")
    with open(state_path, "w") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
    os.chmod(state_path, 0o600)
    print(f"{args.user} 用量已清零(原 {was / GIB:.2f} GiB)")
    return sync()


def sync() -> int:
    return subprocess.run(
        ["systemctl", "start", "airport-sync.service"], check=False
    ).returncode


def main() -> int:
    parser = argparse.ArgumentParser(prog="airport")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="列出所有用户的用量和状态")
    sub.add_parser("sync", help="立刻跑一次调和")
    show = sub.add_parser("show", help="打印某个用户的订阅链接")
    show.add_argument("user")
    reset = sub.add_parser("reset", help="把某个用户的用量清零")
    reset.add_argument("user")
    args = parser.parse_args()

    if args.cmd == "sync":
        return sync()

    cfg, state, _ = load(os.environ["AIRPORT_CONFIG"])
    handlers = {"status": cmd_status, "show": cmd_show, "reset": cmd_reset}
    return handlers[args.cmd](cfg, state, args)


if __name__ == "__main__":
    sys.exit(main())
