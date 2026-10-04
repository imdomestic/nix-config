#!/usr/bin/env bash
set -euo pipefail

# Launch a real extension host with isolated settings, extensions and fixture files.
repo_dir=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_dir"
home_name=${1:-hank@praxic}
code_bin=${VSCODE_BIN:-}
if [[ -z "$code_bin" ]]; then
  code_bin=$(command -v code || true)
fi
if [[ -z "$code_bin" && -x '/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code' ]]; then
  code_bin='/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code'
fi
if [[ -z "$code_bin" ]]; then
  echo 'Set VSCODE_BIN to the VS Code CLI executable.' >&2
  exit 1
fi

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/nixvim-vscode-check.XXXXXX")
echo "Isolated VS Code test: $test_dir"
nix eval --json \
  ".#homeConfigurations.\"$home_name\".config.programs.vscode.profiles.default.extensions" \
  --apply 'map (extension: extension.drvPath)' > "$test_dir/derivations.json"
python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))))' \
  "$test_dir/derivations.json" > "$test_dir/derivations"
while IFS= read -r extension_drv; do
  nix build --no-link --print-out-paths "$extension_drv^*" >> "$test_dir/packages"
done < "$test_dir/derivations"

python3 - "$test_dir" "$repo_dir" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
repo = Path(sys.argv[2])
for name in ['extensions', 'test-extension', 'user/User', 'workspace']:
    (root / name).mkdir(parents=True, exist_ok=True)
for package in (root / 'packages').read_text().splitlines():
    for extension in (Path(package) / 'share/vscode/extensions').iterdir():
        (root / 'extensions' / extension.name).symlink_to(extension)
(root / 'test-extension/package.json').write_text(json.dumps({
    'name': 'nixvim-verification', 'publisher': 'hank', 'version': '0.0.1',
    'engines': {'vscode': '^1.96.0'},
}))
(root / 'test-extension/test.cjs').write_text((repo / 'scripts/test-vscode-neovim.cjs').read_text())
(root / 'user/User/settings.json').write_text(json.dumps({
    'security.workspace.trust.enabled': False,
    'extensions.experimental.affinity': {'asvetliakov.vscode-neovim': 1},
    'update.mode': 'none', 'extensions.autoCheckUpdates': False,
    'extensions.autoUpdate': False, 'workbench.startupEditor': 'none',
    'telemetry.telemetryLevel': 'off',
}))
(root / 'workspace/a.js').write_text('function alpha() {\n  return 1;\n}\n\nfunction beta() {\n  return 2;\n}\n')
(root / 'workspace/b.txt').write_text('alpha beta\n')
PY

test_status=0
"$code_bin" --wait --new-window --user-data-dir "$test_dir/user" \
  --extensions-dir "$test_dir/extensions" \
  --extensionDevelopmentPath="$test_dir/test-extension" \
  --extensionTestsPath="$test_dir/test-extension/test.cjs" \
  --skip-welcome --skip-release-notes --disable-workspace-trust \
  "$test_dir/workspace" > "$test_dir/run.log" 2>&1 || test_status=$?

if [[ -f "$test_dir/result.json" ]]; then
  cat "$test_dir/result.json"
  python3 - "$test_dir/result.json" <<'PY'
import json
import sys
sys.exit(0 if json.load(open(sys.argv[1]))['ok'] else 1)
PY
else
  cat "$test_dir/run.log"
  exit 1
fi
exit "$test_status"
