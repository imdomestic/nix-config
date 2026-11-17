#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
models=$(mktemp)
trap 'rm -f "$models"' EXIT
nix eval --raw '.#homeConfigurations."hank@praxic".config.home.file.".pi/agent/models.json".text' > "$models"
python3 - "$models" <<'PY'
import json
import sys

providers = json.load(open(sys.argv[1]))["providers"]
agy = providers["agy"]
assert agy["api"] == "google-generative-ai"
assert agy["baseUrl"] == "https://gizmo.inner.imdomestic.com/agy/v1beta"
assert agy["apiKey"].startswith("!") and "agy-proxy/api_key" in agy["apiKey"]
assert len(agy["models"]) == 8
by_id = {model["id"]: model for model in agy["models"]}
assert len(by_id) == 8
chat = providers["agy-completions"]
assert chat["api"] == "openai-completions"
assert chat["baseUrl"] == "https://gizmo.inner.imdomestic.com/agy/v1"
assert chat["apiKey"] == agy["apiKey"]
assert {m["id"] for m in chat["models"]} == set(by_id)
for model in chat["models"]:
    assert model["name"] == "agy-completions/" + model["id"]
    assert model["thinkingLevelMap"] == by_id[model["id"]]["thinkingLevelMap"]
    assert model["compat"] == {"supportsDeveloperRole": False, "supportsReasoningEffort": True, "thinkingFormat": "openai"}
for model in agy["models"]:
    assert model["name"] == "agy/" + model["id"]
    assert model["contextWindow"] == 1048576
    assert "compat" not in model and model.get("api", agy["api"]) == "google-generative-ai"
    assert model["maxTokens"] in (65535, 65536)
    assert model["cost"]["input"] > 0
for level in ["low", "medium", "high", "xhigh"]:
    model = by_id["gemini-4-hydrogen-" + level]
    assert {k: v for k, v in model["thinkingLevelMap"].items() if v is not None} == {level: level}
assert not any("gemini" in model["id"].lower() for model in providers["cliproxy"]["models"])
assert any(model["id"] == "gpt-6.1-sol" for model in providers["cliproxy"]["models"])
assert any(model["id"].startswith("rewind/") for model in providers["cliproxy"]["models"])
assert any(model["id"].startswith("opencode/") for model in providers["cliproxy"]["models"])
print("Pi agy + agy-completions: 8 models each, native/Chat routing, exact provider/id names, preset effort maps; no CLIProxy Gemini")
PY
python3 -B scripts/test-migrate-pi-agy.py
