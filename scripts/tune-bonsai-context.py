import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import time

import httpx


spec = importlib.util.spec_from_file_location('verify_bonsai', Path(__file__).with_name('verify-bonsai.py'))
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)
parser = argparse.ArgumentParser()
parser.add_argument('--settings', type=Path, required=True)
parser.add_argument('--model', choices=['bonsai-main', 'bonsai-hikari'], required=True)
parser.add_argument('--context', type=int, required=True)
parser.add_argument('--draft-cache', choices=['q8_0'])
parser.add_argument('--batch-size', type=int)
parser.add_argument('--ubatch-size', type=int)
parser.add_argument('--corpus', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--api-key-file', type=Path, default=Path.home() / '.config/sops-nix/secrets/bonsai/api_key')
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
temporary = args.output / 'temp'
temporary.mkdir(exist_ok=True)
settings = json.loads(args.settings.read_text())
command = shlex.split(settings['models'][args.model]['cmd'])
command[command.index('--ctx-size') + 1] = str(args.context)
command[command.index('--port') + 1] = '5850'
if args.draft_cache:
    command.extend(['--cache-type-k-draft', args.draft_cache, '--cache-type-v-draft', args.draft_cache])
for option, value in (('--batch-size', args.batch_size), ('--ubatch-size', args.ubatch_size)):
    if value is not None:
        command[command.index(option) + 1] = str(value)
key = args.api_key_file.read_text().strip()
with httpx.Client(timeout=30, trust_env=False, headers={'Authorization': f'Bearer {key}'}) as client:
    response = client.get('http://127.0.0.1:8080/unload')
    response.raise_for_status()
processes = subprocess.run([
    'nvidia-smi', '--query-compute-apps=pid', '--format=csv,noheader',
], check=True, capture_output=True, text=True).stdout.strip()
assert not processes, processes
environment = os.environ | {'TMPDIR': str(temporary), 'CUDA_CACHE_PATH': str(temporary / 'cuda')}
log_path = args.output / 'server.log'
record = {'model': args.model, 'context': args.context, 'command': command}
with log_path.open('w') as log, verify.MemoryMonitor() as monitor:
    started = time.perf_counter()
    server = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=environment)
    try:
        deadline = time.monotonic() + 300
        ready = False
        while time.monotonic() < deadline:
            assert server.poll() is None, log_path.read_text()[-6000:]
            health = subprocess.run([
                'curl', '--fail', '--silent', '--max-time', '2', 'http://127.0.0.1:5850/health',
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if health.returncode == 0:
                ready = True
                break
            time.sleep(1)
        assert ready, log_path
        record['startup_seconds'] = time.perf_counter() - started
        with httpx.Client(timeout=900, trust_env=False) as client:
            result = verify.long_context(
                client, '', args.model, args.corpus, args.context,
                upstream_url='http://127.0.0.1:5850',
            )
            record.update(result)
    finally:
        if server.poll() is None:
            server.terminate()
            server.wait(timeout=30)
        record['gpu_peak_mib'] = max(item['used_mib'] for item in monitor.samples)
        record['minimum_free_mib'] = min(item['free_mib'] for item in monitor.samples)
        record['gpu_samples'] = monitor.samples
        (args.output / 'result.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
assert record['minimum_free_mib'] >= 600, record['minimum_free_mib']
print(json.dumps({key: record[key] for key in (
    'model', 'context', 'input_tokens', 'prefill_seconds', 'gpu_peak_mib', 'minimum_free_mib',
)}), flush=True)
