import argparse
import json
import statistics
from pathlib import Path
from runpy import run_path

Verification = run_path(str(Path(__file__).with_name("verify-bonsai.py")))["Verification"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--model", required=True)
    parser.add_argument("--draft", type=int, choices=[3, 5], required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verification = Verification(args.base_url, args.output, None)
    prompt = (
        "Write a complete Python module implementing a TTL-aware LRU cache using the standard library. "
        "The constructor takes capacity, ttl_seconds and a clock callable. "
        "Provide get(key), put(key, value), and __len__; expired entries must never be returned. "
        "Use a monotonic clock by default. Reject invalid capacity and TTL values. "
        "Include unittest cases for eviction order, expiry and updating an existing key. "
        "Explain time complexity in comments. Return the implementation and tests."
    )
    results = []
    for repeat in range(3):
        response = verification.chat(
            f"coding-{repeat}", args.model, [{"role": "user", "content": prompt}],
            reasoning_effort="medium", seed=20261005 + repeat, max_tokens=16384,
        )
        answer = response["choices"][0]["message"]["content"]
        assert response["choices"][0]["finish_reason"] == "stop", (
            f"coding-{repeat}: finish_reason={response['choices'][0]['finish_reason']}; "
            f"response saved under {args.output}"
        )
        assert "def " in answer and "unittest" in answer and len(answer) > 500, answer
        timing = response["timings"]
        results.append({
            "repeat": repeat, "draft_tokens": args.draft,
            "completion_tokens": response["usage"]["completion_tokens"],
            "decode_tokens_per_second": timing["predicted_per_second"],
            "decode_seconds": timing["predicted_ms"] / 1000,
            "prefill_seconds": timing["prompt_ms"] / 1000,
            "drafted_tokens": timing["draft_n"], "accepted_tokens": timing["draft_n_accepted"],
        })
    report = {
        "model": args.model, "draft_tokens": args.draft, "context": 174080,
        "median_decode_tokens_per_second": statistics.median(
            result["decode_tokens_per_second"] for result in results),
        "runs": results,
    }
    verification.record("benchmark", report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
