#!/usr/bin/env python3
"""把 Xray 的 friends-in 入口调和成配置声明的样子。

每次运行做四件事：给新用户签发凭据、把 Xray 的流量计数收进本地账本、
算出谁还该在线、然后用 HandlerService 增删用户使实际状态与之一致。

设计成幂等的：Xray 一重启，friends-in 就回到配置里的空 clients 列表，
所以这个脚本既跑在 timer 上，也绑在 xray.service 上，两条路径都靠
「读实际状态 → 算差集 → 只补差」收敛，重复跑不会有副作用。

几个从 xray 26.3 实测出来、不照做就会出错的地方：
  * `api adu` 吃的是一份完整 xray 配置（读 inbounds[]），不是扁平的 user 对象；
    email 为空的 client 会被静默跳过。
  * `api inbounduser` 在没有用户时返回 `{}`,不是 `{"users": []}`。
  * `api statsquery -reset` 把计数清零后,下次返回的条目会整个缺掉 `value` 键,
    而不是给 0,所以取值必须带默认。
  * `api statsonline` 在用户没有活跃会话时以非零状态退出并打到 stderr。
  * rmu 掉的用户,其流量计数器仍然保留,所以踢人不会丢掉最后一段用量。
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import tempfile
import uuid
from datetime import date, datetime
from typing import Any
from zoneinfo import ZoneInfo

GIB = 1024**3


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


class Xray:
    """`xray api` 子命令的薄封装。"""

    def __init__(self, binary: str, address: str) -> None:
        self.binary = binary
        self.address = address

    def _run(self, subcommand: str, *args: str) -> subprocess.CompletedProcess[str]:
        # -s 必须紧跟子命令:adu 用 CustomFlags 解析,把尾部参数一律当文件名,
        # 放在末尾会让它去找一个叫 "-s" 的文件。
        return subprocess.run(
            [self.binary, "api", subcommand, "-s", self.address, *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def _run_json(self, subcommand: str, *args: str) -> dict[str, Any]:
        proc = self._run(subcommand, *args)
        if proc.returncode != 0:
            raise RuntimeError(f"xray api {subcommand} 失败: {proc.stderr.strip()}")
        return json.loads(proc.stdout or "{}")

    def collect_traffic(self) -> dict[str, dict[str, int]]:
        """取走每用户的流量增量并清零。

        -reset 让计数从零重新开始,所以返回的是「上次调用以来」的增量,
        调用方必须把它累加进持久账本,否则这段用量就永远丢了。
        """
        stats = self._run_json("statsquery", "-pattern", "user>>>", "-reset")
        out: dict[str, dict[str, int]] = {}
        for entry in stats.get("stat") or []:
            name = entry.get("name", "")
            parts = name.split(">>>")
            # user>>><email>>>>traffic>>><uplink|downlink>
            if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
                continue
            # 清零后的条目没有 value 键,不能用 entry["value"]
            out.setdefault(parts[1], {})[parts[3]] = int(entry.get("value", 0) or 0)
        return out

    def current_users(self, tag: str) -> set[str]:
        users = self._run_json("inbounduser", "-tag", tag)
        # 入口没有用户时返回 {},users 键根本不存在
        return {u["email"] for u in (users.get("users") or []) if u.get("email")}

    def add_users(self, tag: str, port: int, clients: list[dict[str, str]]) -> None:
        """adu 要一份完整 xray 配置;port 只是为了让 inbound 能 Build() 通过。"""
        payload = {
            "inbounds": [
                {
                    "tag": tag,
                    "port": port,
                    "protocol": "vless",
                    "settings": {"decryption": "none", "clients": clients},
                }
            ]
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(payload, fh)
            path = fh.name
        try:
            proc = self._run("adu", path)
            if proc.returncode != 0:
                raise RuntimeError(f"adu 失败: {proc.stderr.strip()}")
            # 用户已存在不算错误:并发或重复调用时会撞上,收敛结果仍然正确
            for line in proc.stdout.splitlines():
                if "rpc error" in line and "already exists" not in line:
                    raise RuntimeError(f"adu 报错: {line}")
        finally:
            os.unlink(path)

    def remove_user(self, tag: str, email: str) -> None:
        proc = self._run("rmu", "-tag", tag, email)
        combined = proc.stdout + proc.stderr
        if proc.returncode != 0 and "not found" not in combined:
            raise RuntimeError(f"rmu {email} 失败: {combined.strip()}")

    def online_ips(self, email: str) -> list[str]:
        """用户当前的在线 IP。没有活跃会话时 xray 以非零状态退出,视作空。"""
        proc = self._run("statsonlineiplist", "-email", email)
        if proc.returncode != 0:
            return []
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return []
        ips = data.get("ips")
        return list(ips.keys()) if isinstance(ips, dict) else list(ips or [])


def load_state(path: str) -> dict[str, Any]:
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {"users": {}}
    except json.JSONDecodeError:
        # 账本损坏时保守起见另存备份,不要静默丢掉用量记录
        os.replace(path, path + ".corrupt")
        log(f"账本损坏,已备份到 {path}.corrupt,从空账本重建")
        return {"users": {}}


def save_state(path: str, state: dict[str, Any]) -> None:
    """原子写。中途崩溃最多丢一个采集周期,不会留下半截文件。"""
    directory = os.path.dirname(path)
    with tempfile.NamedTemporaryFile(
        "w", dir=directory, delete=False, prefix=".state-"
    ) as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
        tmp = fh.name
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def verdict(user_cfg: dict[str, Any], used: int, today: date) -> tuple[bool, str]:
    """该用户现在是否应该能连,以及不能连的原因。"""
    if not user_cfg.get("enabled", True):
        return False, "已在配置中停用"
    expires = user_cfg.get("expires")
    if expires and today > date.fromisoformat(expires):
        return False, f"已于 {expires} 到期"
    quota = int(user_cfg.get("quotaGB", 0)) * GIB
    if quota and used >= quota:
        return False, f"用量超限 ({used / GIB:.2f}/{quota / GIB:.0f} GiB)"
    return True, ""


def main() -> int:
    with open(os.environ["AIRPORT_CONFIG"]) as fh:
        cfg = json.load(fh)

    state_path = os.path.join(cfg["stateDir"], "state.json")
    state = load_state(state_path)
    users_state: dict[str, Any] = state.setdefault("users", {})

    xray = Xray(cfg["xrayBin"], cfg["apiAddress"])
    tag = cfg["inboundTag"]
    port = cfg["server"]["port"]
    today = datetime.now(ZoneInfo(cfg.get("timezone", "Asia/Shanghai"))).date()

    # 1. 给新用户签发凭据。UUID 和订阅 token 都在这里生成并只存在 state 里,
    #    这样加朋友只要改 Nix,不用动 sops。
    for name in cfg["users"]:
        entry = users_state.setdefault(name, {})
        if not entry.get("uuid"):
            entry["uuid"] = str(uuid.uuid4())
            entry["token"] = secrets.token_hex(16)
            entry["up"] = 0
            entry["down"] = 0
            entry["createdAt"] = datetime.now(tz=ZoneInfo("UTC")).isoformat()
            log(f"为 {name} 签发了新凭据")

    # 2. 收流量。先入账再做别的,避免中途异常把这一轮增量丢掉。
    try:
        for email, traffic in xray.collect_traffic().items():
            entry = users_state.get(email)
            if entry is None:
                # 配置里已经删掉的用户,计数器还在往上走,记一笔就行
                log(f"忽略未知用户的流量: {email}")
                continue
            entry["up"] = entry.get("up", 0) + traffic.get("uplink", 0)
            entry["down"] = entry.get("down", 0) + traffic.get("downlink", 0)
    except RuntimeError as exc:
        # 收不到统计就不要继续往下走:否则会把所有人都当成零用量而错误地放行
        log(f"采集流量失败,本轮跳过调和: {exc}")
        save_state(state_path, state)
        return 1

    # 3. 算出应该在线的人
    desired: dict[str, dict[str, str]] = {}
    for name, user_cfg in cfg["users"].items():
        entry = users_state[name]
        used = entry.get("up", 0) + entry.get("down", 0)
        ok, reason = verdict(user_cfg, used, today)
        entry["active"] = ok
        entry["reason"] = reason
        if ok:
            client = {"id": entry["uuid"], "email": name}
            if cfg["server"].get("flow"):
                client["flow"] = cfg["server"]["flow"]
            desired[name] = client

    save_state(state_path, state)

    # 4. 调和。只补差集,所以重复运行是安全的。
    try:
        current = xray.current_users(tag)
    except RuntimeError as exc:
        log(f"读取当前用户失败: {exc}")
        return 1

    to_add = [c for name, c in desired.items() if name not in current]
    to_remove = sorted(current - set(desired))

    if to_add:
        xray.add_users(tag, port, to_add)
        log(f"放行: {', '.join(sorted(c['email'] for c in to_add))}")
    for email in to_remove:
        xray.remove_user(tag, email)
        reason = users_state.get(email, {}).get("reason") or "不在配置中"
        log(f"停用 {email}: {reason}")

    if not to_add and not to_remove:
        log(f"已一致,{len(desired)} 个用户在线")
    return 0


if __name__ == "__main__":
    sys.exit(main())
