#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
llm=$(mktemp)
trap 'rm -f "$llm"' EXIT
nix eval --json .#nixosConfigurations.tank.config.services.maxx.settings.llm > "$llm"
python3 - "$llm" <<'PY'
import json
import sys

llm = json.load(open(sys.argv[1]))
provider = llm['providers']['agy-completions']
assert provider['protocol'] == 'chat'
assert provider['base_url'] == 'https://gizmo.inner.imdomestic.com/agy/v1'
assert provider['retries'] == 0
assert provider['api_key_file'] == '/run/secrets/maxx/agy-completions-api-key'
assert len(provider['models']) == 14
for family in ['argon', 'carbon']:
    for level in ['low', 'medium', 'high']:
        model = provider['models'][f'gemini-4-{family}-{level}']
        assert model['context_window'] == 262144
        assert model['max_output'] == 65536
        assert not model.get('video', False)
    assert f'gemini-4-{family}-xhigh' not in provider['models']
for level in ['low', 'medium', 'high', 'xhigh']:
    assert f'gemini-4-hydrogen-{level}' in provider['models']
assert llm['default']['model'] == 'cliproxy/gemini-3.8-flash-high'
assert llm['dreamer']['model'] == 'cliproxy/gemini-3.8-flash-high'
assert llm['caption']['model'] == 'cliproxy-responses/gpt-5.6-luna'
assert llm['job']['model'] == 'cliproxy-responses/gpt-6.1-sol'
assert not any(model.startswith(('vertex/', 'vertex-c820/'))
               for entry in llm['providers'].values() for model in entry['models'])
assert not any('vertex/' in json.dumps(llm[role]) or 'vertex-c820/' in json.dumps(llm[role])
               for role in ['default', 'intent', 'dreamer', 'caption', 'job'])
print('Max agy-completions: 14 models, all 6 Argon/Carbon presets, no fake XHigh or Vertex routes; defaults preserved')
PY
