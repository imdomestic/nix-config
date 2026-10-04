import argparse
import hashlib
import json
import os
import runpy
import sys
from collections import Counter
from pathlib import Path

source = Path(os.environ["ZATFUNG_ROOT"])
sys.path.insert(0, str(source))
from tools.artifact import Artifact


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("state", type=Path)
    args = parser.parse_args()
    packer = runpy.run_path(str(source / "tools/ternary-convert/pack_zatfung.py"))
    models = [
        ("bonsai-main", "Ternary-Bonsai-2-27B-Abliterated-v2-PQ2_0.gguf", "e25d197aa62ce0a2"),
        ("bonsai-hikari", "Ternary-Bonsai-2-27B-Abliterated-PQ2_0.gguf", "e7f6daf95ab820ef"),
    ]
    results = []
    with Artifact.open(args.state / "inputs/qwen3_8_27b-v2-dc370fb6295a.ninfer") as template:
        for model, filename, revision in models:
            gguf = packer["Gguf"](str(args.state / "inputs" / filename))
            assert gguf.n_tensors == 851, gguf.n_tensors
            assert not any(name.startswith("blk.64.") for name in gguf.tensor)
            gguf.f.close()
            with Artifact.open(args.state / "models" / f"{model}-{revision}.ninfer") as artifact:
                borrowed = [obj for obj in artifact.objects
                            if not obj.name.startswith("text/") or obj.name in {
                                "text/draft_head", "text/draft_head_token_ids"}]
                assert len(borrowed) == 419, len(borrowed)
                for obj in borrowed:
                    assert hashlib.sha256(artifact.payload(obj)).digest() == hashlib.sha256(
                        template.payload(obj.name)).digest(), obj.name
                results.append({
                    "model": model, "source_tensors": gguf.n_tensors,
                    "source_header_end": gguf.header_end, "artifact_bytes": artifact.file_bytes,
                    "artifact_objects": len(artifact.objects), "borrowed_objects": len(borrowed),
                    "borrowed_groups": dict(Counter(obj.name.split("/")[0] for obj in borrowed)),
                    "all_borrowed_payloads_match_template": True,
                })
    report = json.dumps(results, indent=2) + "\n"
    (args.state / "logs/artifact-audit.json").write_text(report)
    print(report)


if __name__ == "__main__":
    main()
