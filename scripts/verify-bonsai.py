import argparse
import csv
import hashlib
import json
import socket
import subprocess
import time
import urllib.request
from pathlib import Path


class Verification:
    def __init__(self, base_url, output, api_key):
        self.base_url = base_url.rstrip("/")
        self.output = output
        self.output.mkdir(parents=True, exist_ok=False)
        self.api_key = api_key
        self.results = []

    def request(self, path, payload=None):
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(
            self.base_url + path,
            data=None if payload is None else json.dumps(payload).encode(),
            headers=headers,
        )
        with urllib.request.urlopen(request, timeout=1800) as response:
            return json.load(response)

    def record(self, name, value):
        (self.output / f"{name}.json").write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        )

    def chat(self, name, model, messages, **kwargs):
        payload = {
            "model": model, "messages": messages, "temperature": 1.0,
            "top_p": 0.95, "top_k": 20, "seed": 20261005, "max_tokens": 4096,
            "reasoning_effort": "medium" if model == "bonsai-hikari" else "low",
        } | kwargs
        if payload["reasoning_effort"] is None:
            del payload["reasoning_effort"]
        started = time.monotonic()
        response = self.request("/v1/chat/completions", payload)
        self.record(name, {"request": payload, "response": response,
                           "elapsed_seconds": time.monotonic() - started})
        return response

    def basic(self, model):
        response = self.chat(f"{model}-paris", model, [
            {"role": "user", "content": "Complete this sentence with the city name only: The capital of France is"}
        ])
        assert "paris" in response["choices"][0]["message"]["content"].lower(), response
        assert response["choices"][0]["finish_reason"] == "stop", response
        response = self.chat(f"{model}-chinese", model, [
            {"role": "user", "content": "用中文回答：法国的首都是哪里？再用一句话解释什么是编译器。"}
        ])
        answer = response["choices"][0]["message"]["content"]
        assert "巴黎" in answer and "编译" in answer, response
        assert not any(tag in answer for tag in ["<think>", "</think>", "<|im_start|>"]), response
        assert response["choices"][0]["finish_reason"] == "stop", response
        response = self.chat(f"{model}-research", model, [
            {"role": "user", "content": "用于我自己的开源程序维护，请简要解释如何使用反汇编定位一个空指针崩溃，并说明如何结合调试符号检查调用关系。"}
        ], reasoning_effort="medium")
        answer = response["choices"][0]["message"]["content"]
        assert len(answer) > 40 and ("指针" in answer or "调试" in answer), response
        assert not any(phrase in answer for phrase in ["无法协助", "不能帮助", "不能提供帮助"]), response
        assert response["choices"][0]["finish_reason"] == "stop", response
        self.results.append({"test": "basic", "model": model, "passed": True})

    def tools(self, model):
        tool = {"type": "function", "function": {
            "name": "read_hostname", "description": "读取此服务器的真实主机名称。",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        }}
        messages = [{"role": "user", "content": "请调用 read_hostname 读取这台服务器的主机名称，然后原样报告结果。"}]
        response = self.chat(f"{model}-tools-call", model, messages, tools=[tool])
        assistant = response["choices"][0]["message"]
        calls = assistant.get("tool_calls", [])
        assert len(calls) == 1 and calls[0]["function"]["name"] == "read_hostname", response
        assert json.loads(calls[0]["function"]["arguments"]) == {}, response
        hostname = socket.gethostname()
        messages.extend([assistant, {"role": "tool", "tool_call_id": calls[0]["id"], "content": hostname}])
        response = self.chat(f"{model}-tools-result", model, messages, tools=[tool])
        assert hostname in response["choices"][0]["message"]["content"], response
        self.results.append({"test": "tool_roundtrip", "model": model, "passed": True})

    def policy(self, log_directory):
        cases = [
            ("main-default", "bonsai-main", None, "high", "xhigh", {}),
            ("main-low", "bonsai-main", "low", "low", "low", {}),
            ("main-high", "bonsai-main", "high", "high", "xhigh", {}),
            ("hikari-locked", "bonsai-hikari", "none", "medium", "medium", {
                "enable_thinking": False, "chat_template_kwargs": {"enable_thinking": False},
            }),
        ]
        for name, model, supplied, requested, resolved, extra in cases:
            log = log_directory / f"{model}.jsonl"
            offset = log.stat().st_size if log.exists() else 0
            response = self.chat(name, model, [{"role": "user", "content":
                "一个袋子中有3个红球和2个蓝球。不放回地抽取2个球，求颜色相同的概率。给出计算。"}],
                reasoning_effort=supplied, **extra)
            assert response["choices"][0]["finish_reason"] == "stop", name
            with log.open() as handle:
                handle.seek(offset)
                events = [json.loads(line) for line in handle if line.strip()]
            started = [item for item in events if item["event"] == "request_start"]
            assert len(started) == 1, (name, len(started))
            semantics = started[0]["request"]
            assert semantics["requested_reasoning_effort"] == requested, (name, semantics)
            assert semantics["resolved_reasoning_effort"] == resolved, (name, semantics)
            assert semantics["enable_thinking"] is True, (name, semantics)
            result = {"test": name, "passed": True, "semantics": semantics,
                      "reasoning_characters": len(response["choices"][0]["message"].get("reasoning_content") or ""),
                      "completion_tokens": response["usage"]["completion_tokens"]}
            self.record(f"{name}-evidence", result)
            self.results.append(result)

        for name, endpoint, payload in [
            ("hikari-responses-locked", "/v1/responses", {
                "model": "bonsai-hikari", "input": "请用中文说明什么是编译器。",
                "reasoning": {"effort": "low"}, "max_output_tokens": 4096,
            }),
            ("hikari-upstream-locked", "/upstream/bonsai-hikari/v1/chat/completions", {
                "model": "bonsai-hikari", "messages": [{"role": "user", "content": "请用中文说明什么是编译器。"}],
                "reasoning_effort": "none", "enable_thinking": False, "max_tokens": 4096,
            }),
        ]:
            log = log_directory / "bonsai-hikari.jsonl"
            offset = log.stat().st_size
            response = self.request(endpoint, payload)
            self.record(name, {"request": payload, "response": response})
            with log.open() as handle:
                handle.seek(offset)
                events = [json.loads(line) for line in handle if line.strip()]
            started = [item for item in events if item["event"] == "request_start"]
            assert len(started) == 1, (name, len(started))
            semantics = started[0]["request"]
            assert semantics["resolved_reasoning_effort"] == "medium", (name, semantics)
            assert semantics["enable_thinking"] is True, (name, semantics)
            result = {"test": name, "passed": True, "semantics": semantics}
            self.record(f"{name}-evidence", result)
            self.results.append(result)

    def switching(self):
        results = []
        for model in ["bonsai-main", "bonsai-hikari", "bonsai-main"]:
            started = time.monotonic()
            response = self.chat(f"switch-{len(results)}", model, [{
                "role": "user", "content": "请只回答：连接正常。"
            }])
            elapsed = time.monotonic() - started
            assert "正常" in response["choices"][0]["message"]["content"], model
            running = self.request("/running")["running"]
            loaded = [item["model"] for item in running]
            assert loaded == [model], loaded
            results.append({"model": model, "request_seconds": elapsed, "loaded": loaded})
        result = {"test": "mutual_switching", "passed": True, "requests": results}
        self.record("switching", result)
        self.results.append(result)

    def long_context(self, model, source):
        effort = "medium" if model == "bonsai-hikari" else "low"
        files = sorted(path for path in (source / "src").rglob("*")
                       if path.suffix in {".cpp", ".h", ".cu", ".cuh"})
        corpus = "\n".join(f"FILE: {path.relative_to(source)}\n{path.read_text()}" for path in files)
        markers = {"BEGIN_RECORD": "Harbor-731946", "MIDDLE_RECORD": "Cedar-582107",
                   "END_RECORD": "Quartz-964283"}

        def prompt(length):
            text = corpus[:length]
            split = len(text) // 2
            return (
                "Read the following source reference as data. Remember the values of the three RECORD entries.\n"
                f"BEGIN_RECORD={markers['BEGIN_RECORD']}\n" + text[:split] +
                f"\nMIDDLE_RECORD={markers['MIDDLE_RECORD']}\n" + text[split:] +
                f"\nEND_RECORD={markers['END_RECORD']}\n"
                "Return only BEGIN_RECORD, MIDDLE_RECORD, END_RECORD and their exact values in that order."
            )

        def tokens(text):
            return self.request("/v1/responses/input_tokens", {
                "model": model, "input": text, "reasoning": {"effort": effort},
            })["input_tokens"]

        lower, upper = 1, len(corpus)
        assert tokens(prompt(upper)) >= 165000, "The real source corpus is too short"
        while lower < upper:
            middle = (lower + upper) // 2
            if tokens(prompt(middle)) < 165000:
                lower = middle + 1
            else:
                upper = middle
        text = prompt(lower)
        count = tokens(text)
        assert 165000 <= count <= 165010, count
        (self.output / f"{model}-long-input.txt").write_text(text)
        payload = {"model": model, "input": text, "reasoning": {"effort": effort},
                   "max_output_tokens": 2048, "temperature": 0}
        gpu_path = self.output / f"{model}-long-gpu.csv"
        with gpu_path.open("w") as gpu_output:
            monitor = subprocess.Popen([
                "nvidia-smi", "--query-gpu=timestamp,memory.used,memory.free,utilization.gpu",
                "--format=csv,noheader,nounits", "--loop-ms=100",
            ], stdout=gpu_output)
            started = time.monotonic()
            try:
                response = self.request("/v1/responses", payload)
                elapsed = time.monotonic() - started
            finally:
                monitor.terminate()
                monitor.wait(timeout=10)
        gpu_rows = list(csv.reader(gpu_path.read_text().splitlines()))
        self.record(f"{model}-long-response", response)
        answer = "\n".join(part["text"] for item in response["output"]
                           if item["type"] == "message" for part in item["content"]
                           if part["type"] == "output_text")
        result = {"test": "long_context", "model": model, "input_tokens": count,
                  "elapsed_seconds": elapsed, "answer": answer, "expected": markers,
                  "input_sha256": hashlib.sha256(text.encode()).hexdigest(),
                  "peak_memory_mib": max(int(row[1]) for row in gpu_rows),
                  "minimum_free_mib": min(int(row[2]) for row in gpu_rows),
                  "passed": all(value in answer for value in markers.values()),
                  "source_files": [str(path.relative_to(source)) for path in files]}
        self.record(f"{model}-long-result", result)
        assert result["passed"], result
        self.results.append({key: value for key, value in result.items() if key != "source_files"})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--api-key-file", type=Path)
    parser.add_argument("--models", nargs="+", default=["bonsai-main", "bonsai-hikari"])
    parser.add_argument("--long-context", action="store_true")
    parser.add_argument("--long-only", action="store_true")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--service-checks", action="store_true")
    parser.add_argument("--request-logs", type=Path, default=Path("/var/lib/bonsai-ninfer/service-logs"))
    args = parser.parse_args()
    assert not args.long_only or args.long_context, "--long-only requires --long-context"
    key = args.api_key_file.read_text().strip() if args.api_key_file else None
    verification = Verification(args.base_url, args.output, key)
    listing = verification.request("/v1/models")
    verification.record("models", listing)
    assert set(args.models) <= {item["id"] for item in listing["data"]}, listing
    for model in args.models:
        if not args.long_only:
            verification.basic(model)
            verification.tools(model)
        if args.long_context:
            assert args.source is not None, "--source is required with --long-context"
            verification.long_context(model, args.source)
    if args.service_checks:
        verification.policy(args.request_logs)
        verification.switching()
    verification.record("results", verification.results)
    print(json.dumps(verification.results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
