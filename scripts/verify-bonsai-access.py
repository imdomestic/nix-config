import argparse
import json
from pathlib import Path
import socket

import httpx


parser = argparse.ArgumentParser()
parser.add_argument('--url', required=True)
parser.add_argument('--api-key-file', type=Path, default=Path.home() / '.config/sops-nix/secrets/bonsai/api_key')
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
key = args.api_key_file.read_text().strip()
assert key
results = {}
with httpx.Client(timeout=900, trust_env=False) as client:
    for label, headers in (
        ('missing-key', {}),
        ('invalid-key', {'Authorization': 'Bearer invalid-verification-key'}),
    ):
        response = client.get(f'{args.url}/v1/models', headers=headers)
        assert response.status_code == 401, (label, response.status_code)
        results[label] = response.status_code
    client.headers['Authorization'] = f'Bearer {key}'
    response = client.get(f'{args.url}/v1/models')
    response.raise_for_status()
    results['models'] = response.json()
    assert {item['id'] for item in results['models']['data']} == {'bonsai-main', 'bonsai-hikari'}
    response = client.post(f'{args.url}/v1/chat/completions', json={
        'model': 'bonsai-main',
        'messages': [{'role': 'user', 'content': '请用中文简要解释太阳为什么会发光。'}],
        'max_tokens': 4096, 'seed': 20261004,
    })
    response.raise_for_status()
    results['chinese'] = response.json()
    answer = results['chinese']['choices'][0]['message']['content']
    assert answer and any('\u4e00' <= char <= '\u9fff' for char in answer), answer
    assert results['chinese']['choices'][0]['finish_reason'] == 'stop'
    messages = [{'role': 'user', 'content': '请调用 get_client_hostname，然后告诉我客户端主机名称。'}]
    tools = [{
        'type': 'function',
        'function': {
            'name': 'get_client_hostname',
            'description': '读取发起请求的客户端真实主机名称。',
            'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False},
        },
    }]
    response = client.post(f'{args.url}/v1/chat/completions', json={
        'model': 'bonsai-main', 'messages': messages, 'tools': tools,
        'max_tokens': 4096, 'seed': 20261004,
    })
    response.raise_for_status()
    results['tool-call'] = response.json()
    message = results['tool-call']['choices'][0]['message']
    assert results['tool-call']['choices'][0]['finish_reason'] == 'tool_calls'
    assert message['tool_calls']
    messages.append(message)
    observed = socket.gethostname()
    for call in message['tool_calls']:
        assert call['function']['name'] == 'get_client_hostname'
        assert json.loads(call['function']['arguments']) == {}
        messages.append({'role': 'tool', 'tool_call_id': call['id'], 'content': json.dumps({'hostname': observed})})
    response = client.post(f'{args.url}/v1/chat/completions', json={
        'model': 'bonsai-main', 'messages': messages, 'tools': tools,
        'max_tokens': 4096, 'seed': 20261004,
    })
    response.raise_for_status()
    results['tool-answer'] = response.json()
    assert observed in results['tool-answer']['choices'][0]['message']['content']
results['status'] = 'passed'
results['client'] = observed
args.output.write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n')
print('API authentication, Chinese response and real tool roundtrip: passed')
