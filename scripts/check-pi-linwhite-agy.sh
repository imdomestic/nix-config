#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
agent=$(mktemp -d)
trap 'rm -rf "$agent"' EXIT
nix eval --raw '.#homeConfigurations."linwhite@aegis".config.home.file.".pi/agent/models.json".text' > "$agent/models.json"
python3 - "$agent/models.json" "$agent/agy-ids.json" <<'PY'
import json
import sys

providers = json.load(open(sys.argv[1]))['providers']
agy = providers['agy']
assert agy['api'] == 'google-generative-ai'
assert agy['baseUrl'] == 'https://gizmo.inner.imdomestic.com/agy/v1beta'
assert agy['apiKey'].startswith('!') and 'agy-proxy/api_key' in agy['apiKey']
models = {m['id']: m for m in agy['models']}
assert len(models) == 8
assert set(models) == {'gemini-3-flash', 'gemini-3.1-flash-lite', 'gemini-3.5-flash-lite', 'gemini-3.8-flash-high'} | {'gemini-4-hydrogen-' + x for x in ('low', 'medium', 'high', 'xhigh')}
for id, model in models.items():
    assert model['name'] == 'agy/' + id
    assert model['contextWindow'] == 1048576 and model['input'] == ['text', 'image']
    assert model['maxTokens'] in (65535, 65536) and model['cost']['input'] > 0
for level in ('low', 'medium', 'high', 'xhigh'):
    model = models['gemini-4-hydrogen-' + level]
    assert {k: v for k, v in model['thinkingLevelMap'].items() if v is not None} == {level: level}
assert {m['id'] for m in providers['cliproxy']['models']} >= set(models)
assert 'agy-completions' not in providers
with open(sys.argv[2], 'w') as f:
    json.dump(list(models), f)
print('linwhite agy: 8 native models; existing CLIProxy models retained')
PY
PI_CODING_AGENT_DIR="$agent" PI_TEST_AGY_MODELS="$agent/agy-ids.json" \
  pi --offline --no-extensions --no-mcp --no-skills --no-prompt-templates \
    --no-context-files --no-approve --no-session --mode rpc \
    -e "$PWD/scripts/check-pi-linwhite-agy.ts" </dev/null
python3 -B scripts/check-pi-compact-prompt.py --linwhite
