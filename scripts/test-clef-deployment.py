#!/usr/bin/env python3
"""Exercise Clef's decision API and sample GPU memory on its SSH host."""

import argparse
import base64
import csv
import json
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.request
import zlib
from pathlib import Path


def red_png(size=256):
    def chunk(kind, data):
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data))
        )

    pixels = (b"\x00" + b"\xff\x00\x00" * size) * size
    image = b"\x89PNG\r\n\x1a\n"
    image += chunk(b"IHDR", struct.pack(">2I5B", size, size, 8, 2, 0, 0, 0))
    image += chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b"")
    return base64.b64encode(image).decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://taipan:8000")
    parser.add_argument("--ssh", default="hank@taipan")
    parser.add_argument("--model", default="clef-27b")
    parser.add_argument("--context", type=int, default=8192)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check-swap", action="store_true")
    args = parser.parse_args()
    samples = []
    sampler = subprocess.Popen(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            args.ssh,
            "nvidia-smi --query-gpu=memory.used,memory.free,utilization.gpu "
            "--format=csv,noheader,nounits -lms 100",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    def collect():
        for row in csv.reader(sampler.stdout):
            samples.append((time.monotonic(), *(int(x.strip()) for x in row)))

    thread = threading.Thread(target=collect, daemon=True)
    thread.start()
    results = []

    def request(name, payload, *, path="/v1/systemone", expected=200):
        start = time.monotonic()
        req = urllib.request.Request(
            args.base_url.rstrip("/") + path,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=300) as response:
                status, body = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, body = error.code, error.read()
        elapsed = time.monotonic() - start
        during = [s for s in samples if start <= s[0] <= start + elapsed]
        result = {
            "name": name,
            "status": status,
            "elapsed_seconds": round(elapsed, 3),
            "gpu_peak_mib": max((s[1] for s in during), default=None),
            "gpu_min_free_mib": min((s[2] for s in during), default=None),
            "response": json.loads(body),
        }
        results.append(result)
        print(json.dumps(result), flush=True)
        allowed = expected if isinstance(expected, tuple) else (expected,)
        assert status in allowed, result
        return result["response"]

    questions = {
        "team": {
            "type": "choice",
            "instructions": "Which team should handle this ticket?",
            "criteria": {
                "billing": "Payments and refunds",
                "technical": "Software bugs",
            },
        },
        "refund": {
            "type": "noul",
            "instructions": "Does the customer request a refund?",
        },
    }
    ticket = (
        "I was charged twice for the same order. Please refund the duplicate payment."
    )

    def decide(name, state, schema=questions):
        response = request(
            name, {"model": args.model, "state": state, "questions": schema}
        )
        if schema is questions:
            assert response["answers"]["team"]["choice"] == "billing", response
            assert response["answers"]["refund"]["noul"] > 0.5, response
        return response

    try:
        deadline = time.monotonic() + 10
        while not samples and time.monotonic() < deadline:
            time.sleep(0.1)
        assert samples, "GPU sampler did not return any data"
        decide("cold_short", ticket)
        decide("warm_short", ticket)
        filler = "Unrelated archive entry: the office inventory was checked.\n"
        decide("long_state", filler * 230 + "\nCurrent customer ticket:\n" + ticket)
        response = decide(
            "near_context",
            "Archive padding; only the final ticket is relevant.\n"
            + " x" * (args.context - 350)
            + "\nCurrent customer ticket:\n"
            + ticket,
        )
        assert args.context - 350 < response["usage"]["input_tokens"] <= args.context
        many = {
            f"refund_{i}": {"type": "noul", "instructions": "Is a refund requested?"}
            for i in range(32)
        }
        response = decide("32_questions", ticket, many)
        assert len(response["answers"]) == 32, response
        response = request(
            "image",
            {
                "model": args.model,
                "state": "Identify the solid color in this image.",
                "images": [red_png()],
                "questions": {
                    "color": {
                        "type": "choice",
                        "instructions": "What color is the image?",
                        "criteria": {"red": "Red", "blue": "Blue", "green": "Green"},
                    }
                },
            },
        )
        assert response["answers"]["color"]["choice"] == "red", response
        response = request(
            "long_state_and_image",
            {
                "model": args.model,
                "state": "Ignore this padding:\n"
                + " x" * (args.context - 1800)
                + "\nIdentify the solid color in this image.",
                "images": [red_png(1024)],
                "questions": {
                    "color": {
                        "type": "choice",
                        "instructions": "What color is the image?",
                        "criteria": {"red": "Red", "blue": "Blue", "green": "Green"},
                    }
                },
            },
        )
        assert response["answers"]["color"]["choice"] == "red", response
        request(
            "context_overflow",
            {
                "model": args.model,
                "state": " x" * args.context,
                "questions": questions,
            },
            expected=(400, 413),
        )
        decide("after_overflow", ticket)
        if args.check_swap:
            request(
                "switch_to_qwen",
                {
                    "model": "qwen3.8-27b-aligned",
                    "messages": [{"role": "user", "content": "Reply with READY."}],
                    "max_tokens": 16,
                    "stream": False,
                    "chat_template_kwargs": {"enable_thinking": False},
                },
                path="/v1/chat/completions",
            )
            decide("switch_back_to_clef", ticket)
        model_status = subprocess.check_output(
            ["ssh", args.ssh, "curl -fsS http://127.0.0.1:11434/api/ps"], text=True
        )
        report = {
            "configured_context": args.context,
            "model": args.model,
            "results": results,
            "ollama_ps": json.loads(model_status),
            "sampling_interval_ms": 100,
            "gpu_peak_mib": max(s[1] for s in samples),
            "gpu_min_free_mib": min(s[2] for s in samples),
        }
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    finally:
        sampler.terminate()
        sampler.wait(timeout=10)
        thread.join(timeout=2)


if __name__ == "__main__":
    main()
