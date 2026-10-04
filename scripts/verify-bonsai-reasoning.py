import argparse
import json
from pathlib import Path
import statistics
import time

import httpx


parser = argparse.ArgumentParser()
parser.add_argument('--url', default='http://127.0.0.1:8080')
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--api-key-file', type=Path, default=Path.home() / '.config/sops-nix/secrets/bonsai/api_key')
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
prompts = [
    '求最小正整数 n，使 n 除以 7 余 3，除以 11 余 5，除以 13 余 7。请给出结果与验证过程。',
    '设计一个幂等付款接口：两个相同订单的并发请求可能在数据库提交后、返回响应前断开连接。请说明事务边界、唯一约束和重试应如何处理，并举出具体的执行顺序。',
    '五个任务 A、B、C、D、E 的耗时分别为 3、2、4、2、3。C 必须在 A 之后，D 必须在 A 和 B 之后，E 必须在 C 和 D 之后。只有两台执行器且任务不可中断，求最短总时间并证明。',
]
records = []
key = args.api_key_file.read_text().strip()
with httpx.Client(timeout=900, trust_env=False, headers={'Authorization': f'Bearer {key}'}) as client:
    for index, prompt in enumerate(prompts):
        for effort in ('low', 'high'):
            started = time.perf_counter()
            response = client.post(f'{args.url}/v1/chat/completions', json={
                'model': 'bonsai-main', 'messages': [{'role': 'user', 'content': prompt}],
                'reasoning_effort': effort, 'temperature': 0, 'seed': 20261005,
                'max_tokens': 16384, 'cache_prompt': False,
            })
            response.raise_for_status()
            result = response.json()
            assert result['choices'][0]['finish_reason'] == 'stop', result
            message = result['choices'][0]['message']
            assert message['content'], result
            reasoning = message.get('reasoning_content') or message.get('reasoning')
            assert reasoning, result
            response = client.post(f'{args.url}/upstream/bonsai-main/tokenize', json={'content': reasoning})
            response.raise_for_status()
            record = {
                'prompt_index': index, 'prompt': prompt, 'effort': effort,
                'reasoning_tokens': len(response.json()['tokens']),
                'elapsed_seconds': time.perf_counter() - started, 'response': result,
            }
            records.append(record)
            (args.output / f'{index}-{effort}.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
            print(json.dumps({key: record[key] for key in ('prompt_index', 'effort', 'reasoning_tokens', 'elapsed_seconds')}), flush=True)
summary = {
    effort: statistics.median(record['reasoning_tokens'] for record in records if record['effort'] == effort)
    for effort in ('low', 'high')
}
(args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
assert summary['high'] > summary['low'], summary
