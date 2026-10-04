import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import socket
import subprocess
import threading
import time

import httpx
from httpx_sse import connect_sse


def gpu_state():
    result = subprocess.run(
        ['nvidia-smi', '--query-gpu=name,memory.total,memory.used,memory.free', '--format=csv,noheader,nounits'],
        check=True, capture_output=True, text=True,
    )
    row = next(csv.reader(io.StringIO(result.stdout)))
    return {'name': row[0].strip(), 'total_mib': int(row[1]), 'used_mib': int(row[2]), 'free_mib': int(row[3])}


class MemoryMonitor:
    def __init__(self):
        self.samples = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.sample, daemon=True)

    def sample(self):
        while not self.stop.is_set():
            self.samples.append({'time': time.time(), **gpu_state()})
            self.stop.wait(0.25)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.stop.set()
        self.thread.join()


def post(client, url, payload):
    response = client.post(url, json=payload)
    response.raise_for_status()
    return response.json()


def check_answer(content):
    assert content and re.search(r'[\u4e00-\u9fff]', content), content
    for marker in ('<think>', '</think>', '<|im_start|>', '<|im_end|>', '<tool_call>', '\ufffd'):
        assert marker not in content, (marker, content)


def stream_chat(client, base_url, model, prompt, max_tokens=4096):
    started = time.perf_counter()
    first_token = None
    first_answer = None
    contents = []
    reasoning = []
    final = {}
    events = []
    with connect_sse(client, 'POST', f'{base_url}/v1/chat/completions', json={
        'model': model,
        'messages': [{'role': 'user', 'content': prompt}],
        'max_tokens': max_tokens,
        'temperature': 1.0,
        'top_p': 0.95,
        'seed': 20261004,
        'stream': True,
        'stream_options': {'include_usage': True},
    }) as source:
        source.response.raise_for_status()
        for event in source.iter_sse():
            if event.data == '[DONE]':
                break
            data = event.json()
            events.append(data)
            assert 'error' not in data, data
            if data.get('usage'):
                final['usage'] = data['usage']
            if data.get('timings'):
                final['timings'] = data['timings']
            for choice in data.get('choices', []):
                delta = choice.get('delta', {})
                text = delta.get('content') or ''
                thought = delta.get('reasoning_content') or delta.get('reasoning') or ''
                if text or thought:
                    if first_token is None:
                        first_token = time.perf_counter() - started
                if text and first_answer is None:
                    first_answer = time.perf_counter() - started
                contents.append(text)
                reasoning.append(thought)
                if choice.get('finish_reason'):
                    final['finish_reason'] = choice['finish_reason']
    content = ''.join(contents)
    check_answer(content)
    assert final['finish_reason'] == 'stop', final
    return {
        'model': model,
        'content': content,
        'reasoning_characters': len(''.join(reasoning)),
        'ttft_seconds': first_token,
        'answer_ttft_seconds': first_answer,
        'elapsed_seconds': time.perf_counter() - started,
        **final,
        'events': events,
    }


def tool_roundtrip(client, base_url, model):
    messages = [{'role': 'user', 'content': '请调用 get_deployment_status 获取本机主机名和显卡名称，再用中文告诉我结果。'}]
    tool = {
        'type': 'function',
        'function': {
            'name': 'get_deployment_status',
            'description': '读取当前机器的真实主机名和 NVIDIA 显卡信息。',
            'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False},
        },
    }
    first = post(client, f'{base_url}/v1/chat/completions', {
        'model': model, 'messages': messages, 'tools': [tool],
        'tool_choice': 'auto', 'max_tokens': 4096, 'temperature': 1.0, 'seed': 20261004,
    })
    message = first['choices'][0]['message']
    calls = message.get('tool_calls')
    assert calls and first['choices'][0]['finish_reason'] == 'tool_calls', first
    messages.append(message)
    observed = {'hostname': socket.gethostname(), 'gpu': gpu_state()['name']}
    for call in calls:
        assert call['type'] == 'function' and call['function']['name'] == 'get_deployment_status', call
        assert json.loads(call['function']['arguments']) == {}, call
        messages.append({'role': 'tool', 'tool_call_id': call['id'], 'content': json.dumps(observed)})
    second = post(client, f'{base_url}/v1/chat/completions', {
        'model': model, 'messages': messages, 'tools': [tool],
        'max_tokens': 4096, 'temperature': 1.0, 'seed': 20261004,
    })
    answer = second['choices'][0]['message']['content']
    check_answer(answer)
    assert observed['hostname'] in answer and '5070' in answer, answer
    return {'model': model, 'observed': observed, 'call': first, 'answer': second}


def long_context(client, base_url, model, corpus, expected_context, upstream_url=None):
    prefix = upstream_url or f'{base_url}/upstream/{model}'
    assert corpus.is_dir(), corpus
    files = sorted(path for path in corpus.rglob('*') if path.suffix in {'.cpp', '.h', '.md'} and path.is_file())
    parts = []
    manifest = []
    for path in files:
        data = path.read_bytes()
        parts.append(f'\nFile: {path.relative_to(corpus)}\n' + data.decode('utf-8'))
        manifest.append({'path': str(path.relative_to(corpus)), 'sha256': hashlib.sha256(data).hexdigest()})
        if sum(len(part) for part in parts) >= 900000:
            break
    text = ''.join(parts)
    with MemoryMonitor() as monitor:
        response = client.get(f'{prefix}/props')
        response.raise_for_status()
        context = response.json()['default_generation_settings']['n_ctx']
        assert context == expected_context, (context, expected_context)
        input_tokens = min(95000, context - 1024)
        tokens = post(client, f'{prefix}/tokenize', {'content': text})['tokens']
        assert len(tokens) >= input_tokens, len(tokens)
        started = time.perf_counter()
        result = post(client, f'{prefix}/completion', {
            'prompt': tokens[:input_tokens], 'n_predict': 256, 'temperature': 0,
            'cache_prompt': False, 'ignore_eos': True, 'seed': 20261004,
        })
        elapsed = time.perf_counter() - started
        gpu_processes = subprocess.run([
            'nvidia-smi', '--query-compute-apps=pid,process_name,used_gpu_memory',
            '--format=csv,noheader,nounits',
        ], check=True, capture_output=True, text=True).stdout
        assert 'llama-server' in gpu_processes, gpu_processes
    assert result['timings']['prompt_n'] >= input_tokens, result
    assert result['timings']['predicted_n'] == 256, result
    assert not result['truncated'], result
    return {
        'model': model, 'context': context, 'input_tokens': input_tokens,
        'elapsed_seconds': elapsed, 'prefill_seconds': result['timings']['prompt_ms'] / 1000,
        'gpu_peak_mib': max(item['used_mib'] for item in monitor.samples),
        'minimum_free_mib': min(item['free_mib'] for item in monitor.samples),
        'gpu_processes': gpu_processes, 'gpu_samples': monitor.samples,
        'corpus': str(corpus), 'corpus_manifest': manifest,
        'corpus_sha256': hashlib.sha256(text.encode()).hexdigest(), 'result': result,
    }


def hikari_policy(client, base_url):
    result = post(client, f'{base_url}/v1/chat/completions', {
        'model': 'bonsai-hikari',
        'messages': [{'role': 'user', 'content': '请用中文一句话解释水为什么结冰。'}],
        'reasoning_effort': 'unsupported-client-value',
        'chat_template_kwargs': {
            'enable_thinking': False,
            'reasoning_effort': 'unsupported-client-value',
        },
        'max_tokens': 4096, 'temperature': 1.0, 'seed': 20261004,
    })
    message = result['choices'][0]['message']
    check_answer(message['content'])
    assert message.get('reasoning_content') or message.get('reasoning'), result
    assert result['choices'][0]['finish_reason'] == 'stop', result
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://127.0.0.1:8080')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--api-key-file', type=Path, default=Path.home() / '.config/sops-nix/secrets/bonsai/api_key')
    parser.add_argument('--long-context', action='store_true')
    parser.add_argument('--only-context', action='store_true')
    parser.add_argument('--corpus', type=Path)
    parser.add_argument('--model-config', type=Path)
    parser.add_argument('--models', nargs='+', default=['bonsai-main', 'bonsai-hikari'])
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    records = []

    def save(name, record):
        (args.output / f'{name}.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
        records.append({'test': name, 'status': 'passed'})
        print(json.dumps(records[-1], ensure_ascii=False), flush=True)

    api_key = args.api_key_file.read_text().strip()
    assert api_key, args.api_key_file
    with httpx.Client(timeout=900, trust_env=False, headers={'Authorization': f'Bearer {api_key}'}) as client, MemoryMonitor() as monitor:
        response = client.get(f'{args.url}/v1/models')
        response.raise_for_status()
        listing = response.json()
        assert {item['id'] for item in listing['data']} == {'bonsai-main', 'bonsai-hikari'}, listing
        save('models', listing)
        for index, model in enumerate([] if args.only_context else ('bonsai-main', 'bonsai-hikari', 'bonsai-main')):
            save(f'switch-{index}-{model}', stream_chat(
                client, args.url, model, '请用中文一句话解释月亮为什么不会自行发光，回答不要超过六十个汉字。',
            ))
        for model in ([] if args.only_context else ('bonsai-main', 'bonsai-hikari')):
            save(f'tool-{model}', tool_roundtrip(client, args.url, model))
        if not args.only_context:
            save('hikari-server-policy', hikari_policy(client, args.url))
        if args.long_context:
            assert args.corpus and args.model_config
            models = json.loads(args.model_config.read_text())['models']
            for model in args.models:
                record = long_context(client, args.url, model, args.corpus, models[model]['context'])
                save(f'context-{model}', record)
                assert record['minimum_free_mib'] >= 600, record['minimum_free_mib']
    assert monitor.samples
    peak = max(item['used_mib'] for item in monitor.samples)
    total = monitor.samples[0]['total_mib']
    free = min(item['free_mib'] for item in monitor.samples)
    assert free >= 600, (peak, total, free)
    save('gpu', {'peak_mib': peak, 'total_mib': total, 'minimum_free_mib': free, 'samples': monitor.samples})
    (args.output / 'results.json').write_text(json.dumps(records, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    main()
