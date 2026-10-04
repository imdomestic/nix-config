import argparse
import csv
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", choices=["main", "hikari"], required=True)
    parser.add_argument("--state", type=Path, default=Path("/var/lib/bonsai-ninfer"))
    parser.add_argument("--draft", type=int, choices=[3, 5], default=3)
    args = parser.parse_args()
    revision = {"main": "e25d197aa62ce0a2", "hikari": "e7f6daf95ab820ef"}[args.model]
    model_id = f"bonsai-{args.model}"
    name = f"{model_id}-capacity-k{args.draft}"
    evidence = args.state / "logs" / name
    evidence.mkdir(parents=True, exist_ok=False)
    image = "localhost/ninfer:bonsai-9c875f71-sm120a"
    argv = [
        "podman", "run", "--detach", "--name", name,
        "--network=host", "--ipc=host", "--device=nvidia.com/gpu=all",
        "--volume", f"{args.state}/models:/models:ro",
        "--volume", f"{evidence}:/logs:rw",
        image, "ninfer-serve", f"/models/{model_id}-{revision}.ninfer",
        "--model-id", model_id, "--host", "127.0.0.1", "--port", "18080",
        "--max-context", "174080", "--kv-capacity", "174080",
        "--kv-dtype", "nvfp4", "--max-concurrency", "1",
        "--spec", "mtp", "--draft-tokens", str(args.draft),
        "--prefill-chunk", "1024", "--preserve-thinking",
        "--max-pending-requests", "16", "--pending-timeout-ms", "600000",
        "--request-log-jsonl", "/logs/requests.jsonl", "--log-level", "debug",
    ]
    (evidence / "command.json").write_text(json.dumps(argv, indent=2) + "\n")
    (evidence / "before.txt").write_text(command("nvidia-smi") + "\n")
    with (evidence / "gpu.csv").open("w") as output:
        monitor = subprocess.Popen([
            "nvidia-smi", "--query-gpu=timestamp,memory.used,memory.free,utilization.gpu",
            "--format=csv,noheader,nounits", "--loop-ms=100",
        ], stdout=output)
        started = time.monotonic()
        try:
            subprocess.run(argv, check=True)
            ready = False
            while time.monotonic() - started < 600:
                state = json.loads(command("podman", "inspect", name))[0]["State"]
                if not state["Running"]:
                    break
                try:
                    with urllib.request.urlopen("http://127.0.0.1:18080/health", timeout=1) as response:
                        ready = json.load(response)["status"] == "ok"
                except (urllib.error.URLError, TimeoutError):
                    # 启动期间健康检查端口尚未接受连接。
                    time.sleep(1)
                    continue
                if ready:
                    break
            elapsed = time.monotonic() - started
        finally:
            monitor.terminate()
            monitor.wait(timeout=10)
    logs = subprocess.run(["podman", "logs", name], text=True, capture_output=True, check=True)
    (evidence / "server.log").write_text(logs.stdout + logs.stderr)
    rows = list(csv.reader((evidence / "gpu.csv").read_text().splitlines()))
    result = {
        "model": model_id, "draft_tokens": args.draft, "ready": ready,
        "startup_seconds": elapsed,
        "peak_memory_mib": max(int(row[1]) for row in rows),
        "minimum_free_mib": min(int(row[2]) for row in rows),
        "container": name, "evidence": str(evidence),
    }
    (evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)
    if not ready:
        print(logs.stdout + logs.stderr, flush=True)
        raise SystemExit("174080 capacity validation failed; stop for the user's decision")
    with urllib.request.urlopen("http://127.0.0.1:18080/v1/models", timeout=10) as response:
        models = json.load(response)
    (evidence / "models.json").write_text(json.dumps(models, indent=2) + "\n")
    assert any(item["id"] == model_id and item["max_model_len"] == 174080 for item in models["data"]), models


if __name__ == "__main__":
    main()
