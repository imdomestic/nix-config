#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

package=$(nix build --no-link --print-out-paths --impure --expr '
  let
    flake = builtins.getFlake (toString ./.);
    pkgs = flake.inputs.nixpkgs.legacyPackages.${builtins.currentSystem};
  in pkgs.callPackage ./pkgs/pi-tintin-subagents {}
')
agent=$(mktemp -d)
trap 'rm -rf "$agent"' EXIT
mkdir -p "$agent/extensions" "$agent/workspace" "$agent/tmp"
nix eval --json --file home/hank/modules/pi/subagents-settings.nix > "$agent/subagents.json"
printf 'export { default } from "%s/src/index.ts";\n' "$package" > "$agent/extensions/tintin-subagents.ts"
printf 'READ_ONLY_FIXTURE\n' > "$agent/workspace/fixture.txt"

TMPDIR="$agent/tmp" PI_CODING_AGENT_DIR="$agent" PI_SUBAGENTS_PACKAGE="$package" \
PI_SUBAGENTS_WORKSPACE="$agent/workspace" \
  pi --offline --no-extensions --no-skills --no-prompt-templates \
    --no-context-files --no-approve --no-session --mode rpc \
    -e "$PWD/scripts/check-pi-subagents.ts" </dev/null
