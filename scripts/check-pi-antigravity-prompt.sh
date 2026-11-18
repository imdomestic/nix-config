#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

agent=$(mktemp -d)
trap 'rm -rf "$agent"' EXIT
nix eval --json --impure --expr '
  let
    flake = builtins.getFlake (toString ./.);
    models = import ./home/hank/modules/pi/agy-models.nix { inherit (flake.inputs.nixpkgs) lib; };
  in map (model: model.id) models
' > "$agent/antigravity-models.json"
PI_CODING_AGENT_DIR="$agent" PI_TEST_ANTIGRAVITY_MODELS="$agent/antigravity-models.json" \
  pi --offline --no-extensions --no-skills --no-prompt-templates \
    --no-context-files --no-approve --no-session --mode rpc \
    -e "$PWD/scripts/check-pi-antigravity-prompt.ts" </dev/null
python3 -B scripts/check-pi-compact-prompt.py
