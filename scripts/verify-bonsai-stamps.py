import argparse
import csv
import json
from pathlib import Path
import statistics
import subprocess
import time


def run_service(unit, action):
    started = time.perf_counter()
    subprocess.run(['systemctl', action, unit], check=True)
    elapsed = time.perf_counter() - started
    invocation = subprocess.run([
        'systemctl', 'show', unit, '--property=InvocationID', '--value',
    ], check=True, capture_output=True, text=True).stdout.strip()
    result = subprocess.run([
        'journalctl', f'_SYSTEMD_INVOCATION_ID={invocation}', '--no-pager', '--output=cat',
    ], check=True, capture_output=True, text=True)
    records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
    assert len(records) == 2, result.stdout
    return {'elapsed_seconds': elapsed, 'records': records}


parser = argparse.ArgumentParser()
parser.add_argument('--config', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
config = json.loads(args.config.read_text())
directory = Path(config['directory'])
model = config['models']['bonsai-main']
target = directory / model['file']
stamp = target.with_name(target.name + '.verified')
before = (target.stat().st_size, target.stat().st_mtime_ns)
fast = [run_service('bonsai-models.service', 'restart') for _ in range(3)]
assert all(record['mode'] == 'stamp' for sample in fast for record in sample['records']), fast
with stamp.open(newline='') as source:
    record = next(csv.DictReader(source))
record['mtime_ns'] = '0'
with stamp.open('w', newline='') as destination:
    writer = csv.DictWriter(destination, fieldnames=list(record))
    writer.writeheader()
    writer.writerow(record)
changed = run_service('bonsai-models.service', 'restart')
assert {record['file']: record['mode'] for record in changed['records']}[target.name] == 'sha256', changed
forced = run_service('bonsai-models-verify.service', 'start')
assert all(record['mode'] == 'sha256' for record in forced['records']), forced
assert before == (target.stat().st_size, target.stat().st_mtime_ns)
dependencies = subprocess.run([
    'systemctl', 'show', 'bonsai-models.service', '--property=After', '--property=Wants',
], check=True, capture_output=True, text=True).stdout
assert 'network-online.target' not in dependencies, dependencies
result = {
    'fast': fast, 'fast_median_seconds': statistics.median(sample['elapsed_seconds'] for sample in fast),
    'changed_stamp': changed, 'forced': forced, 'dependencies': dependencies,
}
args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({
    'fast_median_seconds': result['fast_median_seconds'],
    'changed_stamp_seconds': changed['elapsed_seconds'], 'forced_seconds': forced['elapsed_seconds'],
}), flush=True)
