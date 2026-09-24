#!/usr/bin/env python3
"""Validate text, SSE, tools, vision and near-full-context retrieval on NInfer."""

import argparse
import base64
import json
from pathlib import Path
import re
import struct
import time
import urllib.error
import urllib.request
import uuid
import zlib


def swatches(width=448, height=224):
    """An unambiguous red-left / blue-right image, generated without dependencies."""
    pixels = b"".join(
        b"\0" + b"\xff\0\0" * (width // 2) + b"\0\0\xff" * (width // 2)
        for _ in range(height)
    )

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b"")
    return base64.b64encode(png).decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--model", default="qwen3.8-27b")
    parser.add_argument("--skip-long", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    results = []
    nonce = uuid.uuid4().hex
    image = swatches()

    def post(path, body):
        request = urllib.request.Request(
            args.url.rstrip("/") + path,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            return opener.open(request, timeout=900)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"HTTP {exc.code}: {exc.read().decode()}") from exc

    def chat(name, content, expected=None, tools=None, stream=False):
        body = {
            "model": args.model,
            "messages": [{"role": "user", "content": content}],
            "max_tokens": 512,
            "temperature": 0,
            "reasoning_effort": "none",
            "stream": stream,
        }
        if tools:
            body.update(tools=tools, tool_choice="auto")
        if stream:
            body["stream_options"] = {"include_usage": True}
        started = time.monotonic()
        record = {"test": name}
        with post("/v1/chat/completions", body) as response:
            if stream:
                content_parts, content_events, done = [], 0, False
                usage = {}
                for line in response:
                    if not line.startswith(b"data: "):
                        continue
                    payload = line[6:].strip()
                    if payload == b"[DONE]":
                        done = True
                        break
                    event = json.loads(payload)
                    if event.get("usage"):
                        usage = event["usage"]
                    for choice in event.get("choices", []):
                        part = choice.get("delta", {}).get("content")
                        if part:
                            if not content_events:
                                record["first_content_seconds"] = time.monotonic() - started
                            content_events += 1
                            content_parts.append(part)
                text = "".join(content_parts)
                record.update(content_events=content_events, sse_done=done, usage=usage)
                assert done and content_events > 1, record
            else:
                reply = json.load(response)
                message = reply["choices"][0]["message"]
                text = message.get("content") or ""
                record.update(usage=reply.get("usage"), timings=reply.get("timings"), message=message)
                if tools:
                    calls = message.get("tool_calls", [])
                    assert len(calls) == 1 and calls[0]["function"]["name"] == "report_result", message
                    assert json.loads(calls[0]["function"]["arguments"]) == {"value": 703}, message
        record.update(wall_seconds=time.monotonic() - started, text=text)
        if expected:
            match = re.search(r"\{.*\}", text, re.S)
            assert match and json.loads(match.group()) == expected, text
        record["passed"] = True
        results.append(record)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({"model": args.model, "results": results}, indent=2) + "\n")
        print(json.dumps(record), flush=True)
        return record

    chat("arithmetic", f"Test {nonce}. Return only JSON with the integer value of 37*19: {{\"value\":...}}.",
         {"value": 703})
    chat("python_aliasing", '分析 Python 代码：\ndef f(x, values=[]):\n    values.append(x)\n    return values\na = f(1)\nb = f(2)\n仅返回 JSON，字段 a、b 为最终列表，same 为 a is b 的布尔值。',
         {"a": [1, 2], "b": [1, 2], "same": True})
    chat("sql_nulls", '表 t 仅有列 v，四行值分别为 1、NULL、1、2。执行 SELECT COUNT(*), COUNT(v), COUNT(DISTINCT v), SUM(v) FROM t。仅返回 JSON，依次使用键 rows、nonnull、distinct、sum。',
         {"rows": 4, "nonnull": 3, "distinct": 2, "sum": 4})
    chat("sse", "List the integers from 1 through 40, in order, separated by commas. No commentary.", stream=True)
    chat("tool", "Use report_result to report 37 multiplied by 19. Call the tool, do not answer in prose.",
         tools=[{"type": "function", "function": {
             "name": "report_result", "description": "Report an integer calculation result.",
             "parameters": {"type": "object", "properties": {"value": {"type": "integer"}},
                            "required": ["value"]},
         }}])
    image_part = {"type": "image_url", "image_url": {"url": "data:image/png;base64," + image}}
    chat("vision", [
        {"type": "text", "text": 'Identify the two solid color rectangles. Return only {"left":"color","right":"color"}, using lowercase English color names.'},
        image_part,
    ], {"left": "red", "right": "blue"})

    if not args.skip_long:
        secrets = {"alpha": uuid.uuid4().hex[:12], "beta": uuid.uuid4().hex[:12], "gamma": uuid.uuid4().hex[:12]}

        def prompt(repeats):
            pieces = [f"Document {nonce}. Memorize the three labeled secret codes. Filler is irrelevant.\n"]
            for key in secrets:
                pieces.extend([" neutral" * (repeats // 4), f"\nSECRET {key} = {secrets[key]}\n"])
            pieces.extend([" neutral" * (repeats // 4), '\nReturn only JSON with keys alpha, beta, gamma containing their exact secret codes, plus left and right naming the colors in the attached image in lowercase English.'])
            return "".join(pieces)

        repeats = 259000
        for _ in range(3):
            text = prompt(repeats)
            with post("/v1/messages/count_tokens", {
                "model": args.model, "thinking": {"type": "disabled"},
                "messages": [{"role": "user", "content": [
                    {"type": "text", "text": text},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": image}},
                ]}],
            }) as response:
                count = json.load(response)["input_tokens"]
            if 259000 <= count <= 260000:
                break
            repeats += 259500 - count
        assert 258000 <= count <= 261000, count
        record = chat("long_context_vision", [{"type": "text", "text": text}, image_part],
                      {**secrets, "left": "red", "right": "blue"})
        assert 258000 <= record["usage"]["prompt_tokens"] < 262144, record["usage"]

    print(json.dumps({"passed": True, "tests": len(results), "report": str(args.output)}), flush=True)


if __name__ == "__main__":
    main()
