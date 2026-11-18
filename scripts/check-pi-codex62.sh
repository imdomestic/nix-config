#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
models=$(mktemp)
trap 'rm -f "$models"' EXIT
nix eval --raw '.#homeConfigurations."hank@praxic".config.home.file.".pi/agent/models.json".text' > "$models"
catalog=$(nix build --no-link --print-out-paths --impure --expr '
  let f = builtins.getFlake (toString ./.);
  in f.nixosConfigurations.gizmo.config.services.cliproxy.settings.models.catalog
')
python3 - "$models" "$catalog" <<'PY'
import json
import sys
providers = json.load(open(sys.argv[1]))['providers']
models = {m['id']: m for m in providers['cliproxy']['models']}
catalog = json.load(open(sys.argv[2]))
for id, context, rates in [('gpt-6.2-sol', 500000, (2, 0.1, 2.5, 10)), ('gpt-6.2-astra', 272000, (8, 0.4, 10, 40))]:
    m = models[id]
    assert m['contextWindow'] == context and m['maxTokens'] == 128000
    assert providers['cliproxy']['api'] == 'openai-responses'
    assert m['input'] == ['text', 'image']
    assert {k: v for k, v in m['thinkingLevelMap'].items() if v is not None} == {k: k for k in ['low', 'medium', 'high', 'xhigh', 'max']}
    assert tuple(m['cost'][k] for k in ['input', 'cacheRead', 'cacheWrite', 'output']) == rates
    assert m['cost']['tiers'][0]['inputTokensAbove'] == 272000
    assert m['cost']['tiers'][0]['output'] == rates[-1] * 1.5
    for tier in ['codex-plus', 'codex-pro', 'codex-team']:
        definitions = [entry for entry in catalog[tier] if entry['id'] == id]
        assert len(definitions) == 1
        d = definitions[0]
        assert d['context_length'] == context and d['max_completion_tokens'] == 128000
        assert d['thinking']['levels'] == ['low', 'medium', 'high', 'xhigh', 'max']
    assert not any(entry['id'] == id for entry in catalog['codex-free'])
assert not any(m.startswith('rewind/gpt-6.2') for m in models)
print('GPT 6.2: exact paid Codex IDs, per-model client context, 128K output, five Pi efforts, official prices; no Free/Rewind aliases')
PY
