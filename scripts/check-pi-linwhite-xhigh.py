"""Offline real-Pi/HTTP test of the scoped Hydrogen XHigh adapter."""

import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

models_path, extension_path = map(Path, sys.argv[1:3])
requests = []
fixture = None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        requests.append((self.path, payload))
        is_xhigh = "gemini-4-hydrogen-xhigh" in self.path
        xhigh_requests = sum("gemini-4-hydrogen-xhigh" in path for path, _ in requests)
        if is_xhigh and xhigh_requests == 1:
            parts = [{"functionCall": {"name": "read", "args": {"path": str(fixture)}}, "thoughtSignature": "c2lnbmF0dXJl"}]
        else:
            parts = [{"text": "XHIGH_FIXTURE_OK"}]
        frame = {"candidates": [{"index": 0, "content": {"role": "model", "parts": parts}, "finishReason": "STOP"}], "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2}}
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(("data: " + json.dumps(frame) + "\n\n").encode())


def run(root, model, thinking, extension=True, extra_extension=None):
    command = ["pi", "--offline", "--no-extensions", "--no-mcp", "--no-skills", "--no-prompt-templates", "--no-context-files", "--no-approve", "--no-session", "--tools", "read", "--mode", "json", "--model", "agy/" + model, "--thinking", thinking]
    if extension:
        command += ["-e", str(extension_path)]
    if extra_extension:
        command += ["-e", str(extra_extension)]
    command += ["-p", "Read the fixture and answer."]
    result = subprocess.run(command, cwd=root, env=dict(os.environ, PI_CODING_AGENT_DIR=str(root)), capture_output=True, text=True, timeout=30)
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    messages = [event["message"] for event in events if event.get("type") == "message_end" and event.get("message", {}).get("role") == "assistant"]
    return result, events, messages


def main():
    global fixture
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="pi-agy-xhigh-") as directory:
            root = Path(directory)
            fixture = root / "fixture.txt"
            fixture.write_text("offline fixture\n")
            models = json.loads(models_path.read_text())
            models["providers"] = {"agy": models["providers"]["agy"]}
            models["providers"]["agy"]["baseUrl"] = f"http://127.0.0.1:{server.server_port}/v1beta"
            models["providers"]["agy"]["apiKey"] = "offline-test-key"
            (root / "models.json").write_text(json.dumps(models))
            (root / "settings.json").write_text(json.dumps({"retry": {"enabled": False}}))
            before = len(requests)
            result, _, messages = run(root, "gemini-4-hydrogen-xhigh", "xhigh", extension=False)
            assert len(requests) == before, "XHigh without its adapter must not send a downgraded request"
            assert any("No API provider registered" in m.get("errorMessage", "") for m in messages), (result.stderr, messages)
            override = root / "override.ts"
            override.write_text('export default function(pi) { pi.on("before_provider_request", e => ({ ...e.payload, config: { ...e.payload.config, thinkingConfig: { ...e.payload.config.thinkingConfig, thinkingLevel: "LOW" } } })); }')
            result, _, messages = run(root, "gemini-4-hydrogen-xhigh", "xhigh", extra_extension=override)
            assert len(requests) == before, "Unexpected payload must fail before an HTTP request"
            assert any("Unexpected Pi Google thinking payload" in m.get("errorMessage", "") for m in messages), (result.stderr, messages)
            result, events, messages = run(root, "gemini-4-hydrogen-xhigh", "xhigh")
            assert result.returncode == 0 and len(requests) == before + 2, (result.stderr, messages)
            assert any(e.get("type") == "tool_execution_start" and e.get("toolName") == "read" for e in events)
            assert any("XHIGH_FIXTURE_OK" in c.get("text", "") for m in messages for c in m.get("content", []))
            for path, payload in requests[-2:]:
                assert "gemini-4-hydrogen-xhigh" in path
                assert payload["generationConfig"]["thinkingConfig"]["thinkingLevel"] == "XHIGH", payload.get("generationConfig")
            assert "c2lnbmF0dXJl" in json.dumps(requests[-1][1]), "Native thought signature must survive tool replay"
            result, _, messages = run(root, "gemini-4-hydrogen-high", "high")
            assert result.returncode == 0 and len(requests) == before + 3, (result.stderr, messages)
            assert requests[-1][1]["generationConfig"]["thinkingConfig"]["thinkingLevel"] == "HIGH"
            print("Pi XHigh: native XHIGH on both tool turns; signature replay retained; High unchanged; no adapter means no request")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
