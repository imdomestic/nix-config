"""Merge declared Pi settings while keeping its runtime settings writable."""

import json
import os
import sys
import tempfile
from pathlib import Path


def main():
    target = Path(sys.argv[1])
    settings = json.loads(sys.argv[2])
    document = json.loads(target.read_text(encoding="utf-8")) if target.exists() else {}
    if not isinstance(document, dict):
        raise ValueError("Pi settings must be a JSON object")
    if all(
        key in document and document[key] == value for key, value in settings.items()
    ):
        return
    document.update(settings)

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".settings.json-", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    main()
