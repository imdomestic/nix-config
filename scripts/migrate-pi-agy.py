"""Move only retired CLIProxy Gemini selections to the native agy provider."""

import json
import os
import sys
import tempfile
from pathlib import Path


def migrate(document, models):
    migrated = document.copy()
    by_id = {model["id"]: model["levels"] for model in models}
    if document.get("defaultProvider") == "cliproxy" and document.get("defaultModel") in by_id:
        migrated["defaultProvider"] = "agy"
        levels = by_id[document["defaultModel"]]
        if len(levels) == 1:
            migrated["defaultThinkingLevel"] = levels[0]
    if isinstance(document.get("enabledModels"), list):
        migrated["enabledModels"] = [
            "agy/" + pattern.removeprefix("cliproxy/")
            if isinstance(pattern, str) and pattern.startswith("cliproxy/gemini-")
            else pattern
            for pattern in document["enabledModels"]
        ]
    return migrated


def main():
    path = Path(sys.argv[1])
    if not path.exists():
        return
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("Pi settings must be a JSON object")
    migrated = migrate(document, json.loads(sys.argv[2]))
    if migrated == document:
        return
    fd, temporary = tempfile.mkstemp(prefix=".settings-agy-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(migrated, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    main()
