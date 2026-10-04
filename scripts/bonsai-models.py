import argparse
import csv
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def metadata(path, model):
    stat = path.stat()
    return {'sha256': model['sha256'], 'bytes': str(stat.st_size), 'mtime_ns': str(stat.st_mtime_ns)}


def verified(path, model):
    before = path.stat()
    with path.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    after = path.stat()
    assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), path
    return after.st_size == model['bytes'] and digest == model['sha256']


def prepare(directory, model, force):
    started = time.perf_counter()
    target = directory / model['file']
    stamp = target.with_name(target.name + '.verified')
    if not force and target.is_file() and target.stat().st_size == model['bytes'] and stamp.is_file():
        with stamp.open(newline='') as source:
            records = list(csv.DictReader(source))
        if records == [metadata(target, model)]:
            return {'file': target.name, 'mode': 'stamp', 'seconds': time.perf_counter() - started}
    mode = 'sha256'
    if not target.is_file() or not verified(target, model):
        mode = 'download'
        partial = target.with_name(target.name + '.partial')
        if target.exists():
            partial.unlink(missing_ok=True)
        url = f"https://huggingface.co/{model['repository']}/resolve/{model['revision']}/{model['file']}"
        subprocess.run([
            'curl', '--fail', '--location', '--show-error', '--continue-at', '-',
            '--retry', '12', '--retry-connrefused', '--retry-delay', '5',
            '--connect-timeout', '15', '--output', str(partial), url,
        ], check=True)
        assert verified(partial, model), partial
        partial.chmod(0o644)
        partial.replace(target)
    temporary = stamp.with_name(stamp.name + '.new')
    with temporary.open('w', newline='') as destination:
        record = metadata(target, model)
        writer = csv.DictWriter(destination, fieldnames=list(record))
        writer.writeheader()
        writer.writerow(record)
        destination.flush()
        os.fsync(destination.fileno())
    temporary.replace(stamp)
    return {'file': target.name, 'mode': mode, 'seconds': time.perf_counter() - started}


parser = argparse.ArgumentParser()
parser.add_argument('--config', type=Path, required=True)
parser.add_argument('--force', action='store_true')
args = parser.parse_args()
config = json.loads(args.config.read_text())
directory = Path(config['directory'])
with (directory / '.verification.lock').open('a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    for model in config['models'].values():
        print(json.dumps(prepare(directory, model, args.force)), flush=True)
