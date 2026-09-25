#!/usr/bin/env python3
"""Check aggregate visual admission and real multi-image inference via the gateway."""

import argparse
import base64
import json
from pathlib import Path
import struct
import time
import urllib.error
import urllib.request
import zlib


def solid_image(rgb):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    pixels = (b"\0" + bytes(rgb) * 4096) * 4096
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", 4096, 4096, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b"")
    return "data:image/png;base64," + base64.b64encode(png).decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--budget", type=int, choices=[32768, 49152], default=49152)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--admission-only", action="store_true")
    args = parser.parse_args()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    images = [solid_image(rgb) for rgb in [(255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 0)]]
    count = args.budget // 16384
    records = []

    def post(path, body):
        request = urllib.request.Request(args.url.rstrip("/") + path, data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json"})
        started = time.monotonic()
        try:
            with opener.open(request, timeout=300) as reply:
                return reply.status, json.load(reply), time.monotonic() - started
        except urllib.error.HTTPError as error:
            raw = error.read().decode()
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                body = {"error": {"message": raw}}
            return error.code, body, time.monotonic() - started

    for n, allowed in [(count, True), (count + 1, False)]:
        content = [{"type": "text", "text": "Reply OK."}]
        content += [{"type": "image_url", "image_url": {"url": url}} for url in images[:n]]
        code, body, elapsed = post("/v1/chat/completions", {
            "model": "qwen3.8-27b", "messages": [{"role": "user", "content": content}],
            "temperature": 0, "reasoning_effort": "none", "max_tokens": 1, "stream": False,
        })
        record = {"test": "admission", "images": n, "visual_tokens": n * 16384,
                  "status": code, "response": body, "elapsed_seconds": elapsed}
        records.append(record)
        if allowed:
            assert code == 200 and args.budget <= body["usage"]["prompt_tokens"] < args.budget + 256, record
        else:
            assert code == 400 and body["error"]["code"] == "media_budget_exceeded", record

    if not args.admission_only:
        content = [{"type": "text", "text": "Name the dominant color of each image in order. Only output the color names."}]
        content += [{"type": "image_url", "image_url": {"url": url}} for url in images[:count]]
        code, body, elapsed = post("/v1/chat/completions", {
            "model": "qwen3.8-27b", "messages": [{"role": "user", "content": content}],
            "temperature": 0, "reasoning_effort": "none", "max_tokens": 64, "stream": False,
        })
        record = {"test": "generation", "images": count, "status": code,
                  "response": body, "elapsed_seconds": elapsed}
        records.append(record)
        assert code == 200, record
        text = body["choices"][0]["message"]["content"].lower()
        colors = ["red", "green", "blue"][:count]
        positions = [text.find(color) for color in colors]
        assert all(position >= 0 for position in positions) and positions == sorted(positions), record
        assert args.budget <= body["usage"]["prompt_tokens"] < args.budget + 256, record

    args.output.write_text(json.dumps({"budget": args.budget, "passed": True, "results": records}, indent=2) + "\n")
    print(json.dumps({"budget": args.budget, "passed": True, "results": records}, indent=2))


if __name__ == "__main__":
    main()
