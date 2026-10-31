#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

agent=$(mktemp -d)
trap 'rm -rf "$agent"' EXIT
mkdir -p "$agent/themes"
nix eval --json --file home/hank/modules/pi/themes.nix > "$agent/themes.json"
python3 - "$agent" <<'PY'
import json
import pathlib
import sys

agent = pathlib.Path(sys.argv[1])
for name, theme in json.loads((agent / "themes.json").read_text()).items():
    (agent / "themes" / f"{name}.json").write_text(json.dumps(theme))
PY

for truecolor in 1 0; do
  PI_CODING_AGENT_DIR="$agent" PI_TRUE_COLOR="$truecolor" \
    pi --offline --no-extensions --no-skills --no-prompt-templates \
      --no-context-files --no-approve --no-session --mode rpc \
      -e "$PWD/scripts/check-pi-themes.ts" </dev/null
done
