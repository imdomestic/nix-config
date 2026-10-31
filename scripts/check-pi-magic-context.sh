#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

package=$(nix build --no-link --print-out-paths --impure --expr '
  let
    flake = builtins.getFlake (toString ./.);
    pkgs = flake.inputs.nixpkgs.legacyPackages.${builtins.currentSystem};
  in pkgs.callPackage ./pkgs/pi-magic-context {}
')
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/.config/cortexkit" "$root/agent" "$root/sessions"
settings=$(nix eval --json --file home/hank/modules/pi/magic-context-settings.nix)
config="$root/.config/cortexkit/magic-context.jsonc"
printf '%s\n' '// Preserve this user comment.' '{"historian":{"pi":{"fallback_models":["cliproxy/gpt-5.5"]}},"memory":{"injection_budget_tokens":1234}}' > "$config"
node scripts/merge-jsonc-settings.mjs "$config" "$settings" "$package/node_modules/comment-json"
cp "$config" "$root/first.jsonc"
node scripts/merge-jsonc-settings.mjs "$config" "$settings" "$package/node_modules/comment-json"
cmp "$config" "$root/first.jsonc"
node --input-type=module - "$config" "$package/node_modules/comment-json" <<'JS'
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
const { parse, stringify } = createRequire(import.meta.url)(process.argv[3]);
const raw = readFileSync(process.argv[2], "utf8");
const settings = parse(raw);
assert(raw.includes("// Preserve this user comment."));
assert.equal(settings.auto_update, false);
assert.equal(settings.language, "zh");
assert.equal(settings.historian.pi.model, "cliproxy/gpt-5.5");
assert.deepEqual(Array.from(settings.historian.pi.fallback_models), ["cliproxy/gpt-5.5"]);
assert.equal(settings.memory.injection_budget_tokens, 1234);
assert.equal(settings.embedding.provider, "local");
assert.equal(settings.embedding.local_dtype, "q8");
assert.equal(settings.dreamer.disable, true);
// Smoke tests never download model weights or send an LLM request.
settings.embedding = { provider: "off" };
settings.memory.auto_search = { enabled: false };
writeFileSync(process.argv[2], stringify(settings, null, 2));
JS
printf '%s\n' '{"compaction":{"enabled":false}}' > "$root/agent/settings.json"
printf '%s\n' '{"providers":{"cliproxy":{"baseUrl":"http://127.0.0.1:1/v1","api":"openai-responses","apiKey":"offline-test","models":[{"id":"gpt-5.5","reasoning":true,"contextWindow":1050000,"maxTokens":128000}]}}}' > "$root/agent/models.json"

HOME="$root" XDG_CONFIG_HOME="$root/.config" XDG_DATA_HOME="$root/.local/share" \
PI_CODING_AGENT_DIR="$root/agent" PI_MAGIC_CONTEXT_PACKAGE="$package" \
MAGIC_CONTEXT_STORAGE_DIR="$root/.local/share/cortexkit/magic-context" \
MAGIC_CONTEXT_LOG_PATH="$root/magic-context.log" \
  pi --offline --no-extensions --no-skills --no-prompt-templates --no-context-files \
    --session-dir "$root/sessions" --mode rpc \
    -e "$PWD/scripts/check-pi-magic-context.ts" </dev/null
