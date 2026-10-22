"""Merge declared JSON settings while keeping runtime settings writable."""

import json
import os
import sys
import tempfile
from pathlib import Path


def merge_settings(document, settings):
    merged = document.copy()
    for key, value in settings.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_settings(merged[key], value)
        else:
            merged[key] = value
    return merged


def main():
    target = Path(sys.argv[1])
    settings = json.loads(sys.argv[2])
    document = json.loads(target.read_text(encoding="utf-8")) if target.exists() else {}
    if not isinstance(document, dict):
        raise ValueError("Settings must be a JSON object")
    merged = merge_settings(document, settings)
    if merged == document:
        return

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".settings.json-", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(merged, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    main()
