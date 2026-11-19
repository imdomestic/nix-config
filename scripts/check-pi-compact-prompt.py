"""Offline HTTP-level regression for Pi's model-scoped compact default prompt."""

import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

IDENTITY = "You are a coding assistant running inside pi, a coding agent harness. Help users inspect files, run commands, and modify code."
COMPACT = "you are a coding assistant"
MODEL = "gemini-3.8-flash-high"
LINWHITE = sys.argv[1:] == ["--linwhite"]
if sys.argv[1:] not in ([], ["--linwhite"]):
    raise SystemExit("usage: check-pi-compact-prompt.py [--linwhite]")
MODULE = Path(__file__).resolve().parents[1] / f"home/{'linwhite' if LINWHITE else 'hank'}/modules/pi/antigravity-prompt.ts"
requests = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        requests.append((payload, bool(self.headers.get("X-Agy-Session-Id"))))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        if self.path.startswith("/v1beta/"):
            frame = {"candidates": [{"index": 0, "content": {"role": "model", "parts": [{"text": "OFFLINE_COMPACT_OK"}]}, "finishReason": "STOP"}], "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2}}
        else:
            frame = {"id": "offline", "object": "chat.completion.chunk", "model": MODEL, "choices": [{"index": 0, "delta": {"role": "assistant", "content": "OFFLINE_COMPACT_OK"}, "finish_reason": "stop"}]}
        self.wfile.write(("data: " + json.dumps(frame) + "\n\n").encode())
        if not self.path.startswith("/v1beta/"):
            self.wfile.write(b"data: [DONE]\n\n")


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="pi-compact-http-") as directory:
            root = Path(directory)
            (root / "AGENTS.md").write_text("PROJECT_RULE_SENTINEL: Preserve this entire project instruction.\n")
            (root / "settings.json").write_text(json.dumps({"retry": {"enabled": False, "provider": {"maxRetries": 0}}}))
            extension = root / "probe.ts"
            arguments = "[], [" + json.dumps(MODEL) + "]" if LINWHITE else "[" + json.dumps(MODEL) + "]"
            extension.write_text("import install from " + json.dumps(str(MODULE)) + ";\nexport default function(pi) { install(pi, " + arguments + "); pi.on('before_agent_start', e => { e.systemPromptOptions.sections.fixture = 'CUSTOM_SECTION_SENTINEL'; }); }\n")
            cases = [
                ("agy", "google-generative-ai", None, COMPACT),
                ("other", "openai-completions", None, IDENTITY),
                ("agy", "google-generative-ai", "Explicit custom persona", "Explicit custom persona"),
                ("agy", "google-generative-ai", IDENTITY, IDENTITY),
            ]
            if not LINWHITE:
                cases += [
                    ("agy-completions", "openai-completions", None, COMPACT),
                    ("agy-completions", "openai-completions", IDENTITY, IDENTITY),
                ]
            for provider, api, explicit, expected in cases:
                base = f"http://127.0.0.1:{server.server_port}/" + ("v1beta" if api == "google-generative-ai" else "v1")
                definition = {"baseUrl": base, "api": api, "apiKey": "offline-fixture-not-a-real-key", "models": [{"id": MODEL, "reasoning": True, "maxTokens": 8192}]}
                if api == "openai-completions":
                    definition["compat"] = {"supportsDeveloperRole": False}
                (root / "models.json").write_text(json.dumps({"providers": {provider: definition}}))
                command = ["pi", "--offline", "--no-extensions", "--no-mcp", "--no-skills", "--no-prompt-templates", "--no-approve", "--no-session", "--provider", provider, "--model", MODEL, "--thinking", "high", "--tools", "read", "-e", str(extension), "--append-system-prompt", "APPEND_SENTINEL"]
                if explicit is not None:
                    command += ["--system-prompt", explicit]
                command += ["--print", "Reply OFFLINE_COMPACT_OK without calling tools."]
                before = len(requests)
                result = subprocess.run(command, cwd=root, env=dict(os.environ, PI_CODING_AGENT_DIR=str(root)), capture_output=True, text=True, timeout=25)
                assert result.returncode == 0 and "OFFLINE_COMPACT_OK" in result.stdout, f"Pi process failed for {provider}"
                assert len(requests) == before + 1, "Expected one offline model request"
                payload, has_session = requests[-1]
                if api == "google-generative-ai":
                    prompt = "\n".join(part.get("text", "") for part in payload["systemInstruction"]["parts"])
                    names = [function["name"] for group in payload.get("tools", []) for function in group.get("functionDeclarations", [])]
                else:
                    prompt = "\n".join(message["content"] for message in payload["messages"] if message["role"] in ("system", "developer"))
                    names = [tool["function"]["name"] for tool in payload.get("tools", [])]
                assert prompt.startswith(expected), "Rendered prompt has the wrong preamble"
                assert "PROJECT_RULE_SENTINEL" in prompt and "APPEND_SENTINEL" in prompt and "CUSTOM_SECTION_SENTINEL" in prompt, "Structured context or appended instructions were lost"
                assert "read" in names, "Real provider tool declaration was removed"
                assert has_session == (provider in ("agy", "agy-completions"))
                if explicit is None and provider in ("agy", "agy-completions"):
                    assert IDENTITY not in prompt and "Pi documentation (" not in prompt and "You are Antigravity Agent" not in prompt, "The old default prompt body was retained"
            print(f"Pi compact HTTP ({'linwhite' if LINWHITE else 'hank'}): exact preamble, project/custom/appended sections and tool schemas preserved; other providers and explicit prompts untouched")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
