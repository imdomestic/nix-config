#!/usr/bin/env python3
"""按 token 发订阅。

只监听回环,TLS 和限速交给前面的 nginx。每个用户一条 32 位十六进制 token
路径,认证就靠这条 token,所以比较用 secrets.compare_digest,并且任何
未命中都统一回 404 —— 不区分「token 不存在」和「用户已停用」,免得成为
探测用户名的口子。

每次请求都重新读账本,所以客户端拉订阅时看到的用量是当前值,而不是
服务启动那一刻的快照。
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import urllib.parse
from datetime import date, datetime, time, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

GIB = 1024**3


def read_secret(path: str) -> str:
    with open(path) as fh:
        return fh.read().strip()


class Subscription:
    """把一个用户的凭据渲染成各家客户端认识的格式。"""

    def __init__(self, cfg: dict[str, Any], name: str, entry: dict[str, Any]) -> None:
        self.cfg = cfg
        self.name = name
        self.entry = entry
        server = cfg["server"]
        self.label = server.get("name", "airport")
        self.address = server["address"]
        self.port = server["port"]
        self.sni = server.get("sni", "www.apple.com")
        self.fingerprint = server.get("fingerprint", "chrome")
        self.flow = server.get("flow", "")
        self.public_key = read_secret(server["publicKeyFile"])
        self.short_id = read_secret(server["shortIdFile"])

    def vless_uri(self) -> str:
        query = {
            "type": "tcp",
            "encryption": "none",
            "security": "reality",
            "sni": self.sni,
            "fp": self.fingerprint,
            "pbk": self.public_key,
            "sid": self.short_id,
        }
        if self.flow:
            query["flow"] = self.flow
        return (
            f"vless://{self.entry['uuid']}@{self.address}:{self.port}"
            f"?{urllib.parse.urlencode(query)}#{urllib.parse.quote(self.label)}"
        )

    def base64_bundle(self) -> bytes:
        """v2rayN / NekoBox / Shadowrocket 都吃这个:base64 过的 URI 列表。"""
        return base64.b64encode(self.vless_uri().encode())

    def clash_yaml(self) -> bytes:
        proxy = {
            "name": self.label,
            "type": "vless",
            "server": self.address,
            "port": self.port,
            "uuid": self.entry["uuid"],
            "network": "tcp",
            "udp": True,
            "tls": True,
            "servername": self.sni,
            "client-fingerprint": self.fingerprint,
            "reality-opts": {
                "public-key": self.public_key,
                "short-id": self.short_id,
            },
        }
        if self.flow:
            proxy["flow"] = self.flow
        # 手写 YAML 而不是拉 pyyaml 进来,免得给这么点输出加一个运行时依赖
        lines = ["proxies:"]
        lines.append(f"  - name: {json.dumps(proxy['name'])}")
        for key, value in proxy.items():
            if key == "name":
                continue
            if key == "reality-opts":
                lines.append("    reality-opts:")
                for sub_key, sub_value in value.items():
                    lines.append(f"      {sub_key}: {json.dumps(sub_value)}")
            else:
                lines.append(f"    {key}: {json.dumps(value)}")
        lines += [
            "proxy-groups:",
            "  - name: PROXY",
            "    type: select",
            f"    proxies: [{json.dumps(self.label)}]",
            "rules:",
            "  - MATCH,PROXY",
        ]
        return ("\n".join(lines) + "\n").encode()

    def singbox_json(self) -> bytes:
        outbound = {
            "type": "vless",
            "tag": self.label,
            "server": self.address,
            "server_port": self.port,
            "uuid": self.entry["uuid"],
            "tls": {
                "enabled": True,
                "server_name": self.sni,
                "utls": {"enabled": True, "fingerprint": self.fingerprint},
                "reality": {
                    "enabled": True,
                    "public_key": self.public_key,
                    "short_id": self.short_id,
                },
            },
        }
        if self.flow:
            outbound["flow"] = self.flow
        config = {
            "outbounds": [
                outbound,
                {"type": "direct", "tag": "direct"},
            ],
            "route": {"final": self.label},
        }
        return json.dumps(config, indent=2).encode()

    def userinfo(self, user_cfg: dict[str, Any]) -> str:
        """客户端拿这个头显示「已用 / 总量 / 到期」。"""
        fields = [
            f"upload={self.entry.get('up', 0)}",
            f"download={self.entry.get('down', 0)}",
            f"total={int(user_cfg.get('quotaGB', 0)) * GIB}",
        ]
        expires = user_cfg.get("expires")
        if expires:
            # 到期日当天仍然有效,所以取那天的 23:59:59
            moment = datetime.combine(
                date.fromisoformat(expires), time.max, tzinfo=timezone.utc
            )
            fields.append(f"expire={int(moment.timestamp())}")
        return "; ".join(fields)


class Handler(BaseHTTPRequestHandler):
    server_version = "airport"
    sys_version = ""

    @property
    def cfg(self) -> dict[str, Any]:
        return self.server.airport_cfg  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        # 默认实现会把完整路径写进日志,那里面有 token
        return

    def _not_found(self) -> None:
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _lookup(self, token: str) -> tuple[str, dict[str, Any]] | None:
        state_path = os.path.join(self.cfg["stateDir"], "state.json")
        try:
            with open(state_path) as fh:
                state = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        for name, entry in (state.get("users") or {}).items():
            stored = entry.get("token", "")
            # 定长比较,避免用响应时间猜 token
            if stored and secrets.compare_digest(stored, token):
                if name in self.cfg["users"]:
                    return name, entry
        return None

    def do_GET(self) -> None:  # noqa: N802  (BaseHTTPRequestHandler 的命名)
        parts = [p for p in urllib.parse.urlparse(self.path).path.split("/") if p]
        if not parts or parts[0] != "sub" or len(parts) not in (2, 3):
            return self._not_found()

        found = self._lookup(parts[1])
        if found is None:
            return self._not_found()
        name, entry = found

        sub = Subscription(self.cfg, name, entry)
        fmt = parts[2] if len(parts) == 3 else "base64"
        renderers = {
            "base64": (sub.base64_bundle, "text/plain; charset=utf-8"),
            "clash": (sub.clash_yaml, "text/yaml; charset=utf-8"),
            "singbox": (sub.singbox_json, "application/json"),
        }
        if fmt not in renderers:
            return self._not_found()
        render, content_type = renderers[fmt]
        body = render()

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Subscription-Userinfo", sub.userinfo(self.cfg["users"][name]))
        self.send_header("Profile-Update-Interval", "12")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    with open(os.environ["AIRPORT_CONFIG"]) as fh:
        cfg = json.load(fh)
    listen = cfg["subscription"]["listen"]
    host, _, port = listen.rpartition(":")
    httpd = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler)
    httpd.airport_cfg = cfg  # type: ignore[attr-defined]
    httpd.serve_forever()


if __name__ == "__main__":
    main()
