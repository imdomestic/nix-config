"""Apply Home Manager's Codex settings without discarding runtime settings."""

import os
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

import tomlkit


def merge(target, settings):
    for key, value in settings.items():
        if isinstance(value, Mapping) and isinstance(target.get(key), Mapping):
            merge(target[key], value)
        else:
            target[key] = value


def main():
    target, settings = map(Path, sys.argv[1:])
    original = target.read_text(encoding="utf-8") if target.exists() else ""
    document = tomlkit.parse(original)
    merge(document, tomlkit.parse(settings.read_text(encoding="utf-8")).unwrap())
    updated = tomlkit.dumps(document)
    if updated == original:
        return

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".config.toml-", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(updated)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    main()
