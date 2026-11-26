"""Merge declared JSON settings while keeping runtime settings writable.

Usage: merge-json-settings.py TARGET SETTINGS [--replace KEY]... [--defaults JSON]

SETTINGS is deep-merged. A --replace key takes SETTINGS' value whole, so entries
dropped from the declaration go away. --defaults sets top-level keys only where
the file has none yet, leaving later runtime choices alone.
"""

import argparse
import json
import os
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
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=Path)
    parser.add_argument("settings", type=json.loads)
    parser.add_argument("--replace", action="append", default=[])
    parser.add_argument("--defaults", type=json.loads, default={})
    args = parser.parse_args()
    target = args.target
    document = json.loads(target.read_text(encoding="utf-8")) if target.exists() else {}
    if not isinstance(document, dict):
        raise ValueError("Settings must be a JSON object")
    merged = merge_settings(document, args.settings)
    for key in args.replace:
        if key in args.settings:
            merged[key] = args.settings[key]
    for key, value in args.defaults.items():
        merged.setdefault(key, value)
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
