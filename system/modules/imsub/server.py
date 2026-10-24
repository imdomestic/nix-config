#!/usr/bin/env python3
"""自用订阅:按 token 把已经渲染好的客户端配置发出去。

配置本体由 sops.templates 在 /run 下渲染 —— 六个节点的 UUID 和 Reality
公钥在那一步才落地。所以这个进程既不解密也不拼配置,只做两件事:核对
token,把对应的文件原样吐出去。

token 是唯一的认证,于是:比较用 secrets.compare_digest;token 错、格式名
错、路径不对一律回同一个 404(区分开就是一个探测口子);日志不写请求路径,
BaseHTTPRequestHandler 的默认实现会把带 token 的完整 URL 写进 journal。
"""

from __future__ import annotations

import json
import os
import secrets
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class Handler(BaseHTTPRequestHandler):
    server_version = "imsub"
    sys_version = ""
    # 前面是 nginx,给它长连接用。每条响应都带准确的 Content-Length,
    # 所以升到 1.1 是安全的。
    protocol_version = "HTTP/1.1"

    @property
    def cfg(self) -> dict[str, Any]:
        return self.server.imsub_cfg  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _fail(self, code: int = 404) -> None:
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _authorized(self, token: str) -> bool:
        # 每次请求都重读:sops 换了 token 之后不必记得重启这个服务。
        try:
            with open(self.cfg["tokenFile"]) as fh:
                expected = fh.read().strip()
        except OSError:
            return False
        if not expected:
            return False
        # 比较用 bytes。compare_digest 对 str 要求两边都是 ASCII,而 token
        # 是从 URL 里来的,塞个中文进来就会 TypeError 变成 500 —— 那本身
        # 就把「路径格式对不对」泄露出去了。
        return secrets.compare_digest(expected.encode(), token.encode())

    def _serve(self, *, with_body: bool) -> None:
        parts = [p for p in urllib.parse.urlparse(self.path).path.split("/") if p]
        if len(parts) != 3 or parts[0] != self.cfg["prefix"]:
            return self._fail()
        _, token, fmt = parts

        if not self._authorized(token):
            return self._fail()

        path = self.cfg["formats"].get(fmt)
        if path is None:
            return self._fail()
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except OSError:
            # token 是对的,是这台机器自己没准备好(sops 还没渲染)。
            # 这时候回 404 会让客户端以为订阅没了,进而删掉本地配置。
            return self._fail(503)

        self.send_response(200)
        self.send_header("Content-Type", "text/yaml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # 客户端拿这个当新建配置的默认名字。
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="{self.cfg["profileName"]}-{fmt}.yaml"',
        )
        self.send_header("Profile-Update-Interval", str(self.cfg["updateInterval"]))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if with_body:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802  (BaseHTTPRequestHandler 的命名)
        self._serve(with_body=True)

    # 有些订阅客户端先 HEAD 探一下再 GET;默认实现对 HEAD 回 501,
    # 它们会当成「订阅挂了」。
    def do_HEAD(self) -> None:  # noqa: N802
        self._serve(with_body=False)


def main() -> None:
    with open(os.environ["IMSUB_CONFIG"]) as fh:
        cfg = json.load(fh)
    host, _, port = cfg["listen"].rpartition(":")
    httpd = ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler)
    httpd.imsub_cfg = cfg  # type: ignore[attr-defined]
    httpd.serve_forever()


if __name__ == "__main__":
    main()
