import argparse
import csv
import io
import json
import os
from pathlib import Path
import shlex
import statistics
import subprocess
import time

import httpx
from httpx_sse import connect_sse


def request(client, url, prompt, tokens):
    started = time.perf_counter()
    first_token = None
    timings = None
    usage = None
    with connect_sse(client, 'POST', f'{url}/v1/chat/completions', json={
        'model': 'bonsai-main',
        'messages': [{'role': 'user', 'content': prompt}],
        'max_tokens': tokens,
        'temperature': 0,
        'seed': 20261004,
        'cache_prompt': False,
        'stream': True,
        'stream_options': {'include_usage': True},
    }) as source:
        source.response.raise_for_status()
        for event in source.iter_sse():
            if event.data == '[DONE]':
                break
            data = event.json()
            assert 'error' not in data, data
            if data.get('timings'):
                timings = data['timings']
            if data.get('usage'):
                usage = data['usage']
            for choice in data.get('choices', []):
                delta = choice.get('delta', {})
                if first_token is None and any(delta.get(key) for key in ('content', 'reasoning_content', 'reasoning')):
                    first_token = time.perf_counter() - started
    assert first_token is not None and timings is not None, (first_token, timings, usage)
    return {'ttft_seconds': first_token, 'elapsed_seconds': time.perf_counter() - started, 'timings': timings, 'usage': usage}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    temp_dir = args.output / 'temp'
    temp_dir.mkdir(exist_ok=True)
    settings = json.loads(args.settings.read_text())
    original = shlex.split(settings['models']['bonsai-main']['cmd'])
    prompts = [
        '请用 Python 编写一个斐波那契数列生成器，并解释边界条件和时间复杂度。',
        '请列出五个常见排序算法的名称、时间复杂度和适用场景，输出 JSON 数组。',
        '请用中文解释为什么软件测试需要覆盖边界条件，举出三个具体例子。',
    ]
    results = []
    environment = os.environ | {'TMPDIR': str(temp_dir), 'CUDA_CACHE_PATH': str(temp_dir / 'cuda')}
    for mtp in (False, True):
        command = original.copy()
        command[command.index('--port') + 1] = '5850'
        if not mtp:
            index = command.index('--spec-type')
            del command[index:index + 2]
            index = command.index('--spec-draft-n-max')
            del command[index:index + 2]
        log_path = args.output / f'mtp-{mtp}.log'
        gpu_path = args.output / f'mtp-{mtp}-gpu.csv'
        with log_path.open('w') as log, gpu_path.open('w') as gpu_log:
            startup = time.perf_counter()
            server = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=environment, cwd=args.output)
            monitor = subprocess.Popen([
                'nvidia-smi', '--query-gpu=timestamp,memory.total,memory.used',
                '--format=csv,noheader,nounits', '--loop-ms=250',
            ], stdout=gpu_log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 300
                ready = False
                while time.monotonic() < deadline:
                    assert server.poll() is None, log_path.read_text()[-6000:]
                    status = subprocess.run([
                        'curl', '--fail', '--silent', 'http://127.0.0.1:5850/health',
                    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if status.returncode == 0:
                        ready = True
                        break
                    time.sleep(1)
                assert ready, log_path
                startup_seconds = time.perf_counter() - startup
                with httpx.Client(timeout=600, trust_env=False) as client:
                    warmup = request(client, 'http://127.0.0.1:5850', '请用中文介绍二分查找。', 64)
                    samples = []
                    for index, prompt in enumerate(prompts):
                        sample = request(client, 'http://127.0.0.1:5850', prompt, 384)
                        samples.append(sample)
                        print(json.dumps({'mtp': mtp, 'prompt_index': index, **sample}), flush=True)
            finally:
                server.terminate()
                server.wait(timeout=30)
                monitor.terminate()
                monitor.wait(timeout=10)
        rows = list(csv.reader(io.StringIO(gpu_path.read_text())))
        peak = max(int(row[2]) for row in rows)
        assert int(rows[0][1]) - peak >= 819.2, peak
        result = {
            'mtp': mtp,
            'command': command,
            'startup_seconds': startup_seconds,
            'warmup': warmup,
            'samples': samples,
            'median_tokens_per_second': statistics.median(item['timings']['predicted_per_second'] for item in samples),
            'median_ttft_seconds': statistics.median(item['ttft_seconds'] for item in samples),
            'gpu_peak_mib': peak,
        }
        results.append(result)
        (args.output / 'results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    main()
