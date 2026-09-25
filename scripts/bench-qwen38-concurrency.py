#!/usr/bin/env python3
"""Compare isolated NInfer configurations using identical queued request batches."""

import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import re
import statistics
import threading
import time
import urllib.request


TASKS = [
    "Write a complete Python module implementing a streaming web access-log analyzer. Include parsing, typed records, aggregation by route/status/hour, percentile calculation, CLI arguments, CSV export, and extensive unit tests. Explain the implementation in comments. Produce at least 400 lines of useful code and continue until finished. Do not summarize or omit implementations.",
    "写一篇至少一万字的中文科幻小说：深海维修工程师发现城市供氧系统的异常。通过人物对话、现场动作和逐步调查推进，细致描写不同人物的动机与冲突，不要写提纲，不要提前总结，不要省略中间过程，直接从第一章开始写正文。",
    "Generate a JSON array of 1000 distinct fictional library book records. Each record must have id, title, author, year, genre, shelf, and a one-sentence description. Vary the content, make identifiers sequential, and output the actual records rather than a generator program. Do not abbreviate, explain, or use ellipses.",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--requests", type=int, default=12)
    parser.add_argument("--max-tokens", type=int, default=2048)
    args = parser.parse_args()
    report = {"label": args.label, "requests_per_batch": args.requests,
              "max_tokens": args.max_tokens, "repeats": args.repeats, "batches": []}

    def post(body):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(args.url.rstrip("/") + "/v1/chat/completions",
                                     data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        with opener.open(req, timeout=600) as reply:
            return json.load(reply)

    warmup = {"model": "qwen3.8-27b", "messages": [{"role": "user", "content": "Reply READY."}],
              "max_tokens": 16, "temperature": 0, "reasoning_effort": "none", "stream": False}
    post(warmup)
    for workload in ["count", "mixed"]:
        for repeat in range(args.repeats):
            barrier = threading.Barrier(args.requests)

            def run(index):
                # Stable across configurations, distinct across requests/repetitions.
                nonce = hashlib.sha256(f"qwen-c3-c4-v1/{workload}/{repeat}/{index}".encode()).hexdigest()
                task = ("Write the integers from 1 through 10000 in ascending order, separated by commas. "
                        "Include every integer. Output only the list without explanation.") if workload == "count" else TASKS[index % len(TASKS)]
                body = {"model": "qwen3.8-27b", "messages": [{"role": "user", "content": nonce + "\n" + task}],
                        "max_tokens": args.max_tokens, "temperature": 0 if workload == "count" else 1,
                        "seed": 20260925 + repeat * 100 + index, "reasoning_effort": "none", "stream": False}
                body_hash = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
                barrier.wait()
                started = time.monotonic()
                reply = post(body)
                ended = time.monotonic()
                content = reply["choices"][0]["message"].get("content") or ""
                if workload == "count":
                    assert list(map(int, re.findall(r"\d+", content)))[:100] == list(range(1, 101)), content[:300]
                usage = reply["usage"]
                assert usage["completion_tokens"] > 0, reply
                assert usage.get("prompt_tokens_details", {}).get("cached_tokens", 0) == 0, reply
                return {"index": index, "body_sha256": body_hash, "started_monotonic": started,
                        "ended_monotonic": ended, "wall_seconds": ended - started, "usage": usage,
                        "timings": reply.get("timings", {}), "finish_reason": reply["choices"][0]["finish_reason"],
                        "output_sha256": hashlib.sha256(content.encode()).hexdigest()}

            started_unix = time.time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.requests) as pool:
                rows = list(pool.map(run, range(args.requests)))
            elapsed = max(row["ended_monotonic"] for row in rows) - min(row["started_monotonic"] for row in rows)
            output_tokens = sum(row["usage"]["completion_tokens"] for row in rows)
            drafted = sum(row["timings"].get("draft_n", 0) for row in rows)
            accepted = sum(row["timings"].get("draft_n_accepted", 0) for row in rows)
            batch = {"workload": workload, "repeat": repeat, "started_unix": started_unix,
                     "ended_unix": time.time(), "makespan_seconds": elapsed, "output_tokens": output_tokens,
                     "aggregate_tokens_per_second": output_tokens / elapsed,
                     "median_request_seconds": statistics.median(row["wall_seconds"] for row in rows),
                     "mtp_acceptance": accepted / drafted if drafted else None, "requests": rows}
            report["batches"].append(batch)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps({k: v for k, v in batch.items() if k != "requests"}), flush=True)


if __name__ == "__main__":
    main()
