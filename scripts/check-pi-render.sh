#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

build_package() {
  nix build --no-link --print-out-paths --impure --expr "
    let
      flake = builtins.getFlake (toString ./.);
      pkgs = flake.inputs.nixpkgs.legacyPackages.\${builtins.currentSystem};
    in pkgs.callPackage ./pkgs/$1 {}
  "
}

render=$(build_package pi-better-render)
cc=$(build_package pi-cc-extensions)
subagents=$(build_package pi-tintin-subagents)
agent=$(mktemp -d)
trap 'rm -rf "$agent"' EXIT
nix eval --json --file home/hank/modules/pi/subagents-settings.nix > "$agent/subagents.json"
mkdir -p "$agent/extensions"
printf '%s\n' '{"enableEditorPrefix":false,"enableCustomFooter":false,"enableMarkdownEnhance":false,"excludeRenderers":["Agent","SubagentWorkflow","get_subagent_result","steer_subagent"]}' > "$agent/pi-cc-extensions.json"
nix eval --raw --impure --expr '
  let
    flake = builtins.getFlake (toString ./.);
    pkgs = flake.inputs.nixpkgs.legacyPackages.${builtins.currentSystem};
    module = import ./home/hank/modules/pi { config = {}; inherit pkgs; inherit (pkgs) lib; };
    extensions = builtins.filter (name: pkgs.lib.hasPrefix ".pi/agent/extensions/" name) (builtins.attrNames module.home.file);
  in assert extensions == [ ".pi/agent/extensions/hank-pi.ts" ];
    module.home.file.".pi/agent/extensions/hank-pi.ts".text
' > "$agent/extensions/hank-pi.ts"

PI_CODING_AGENT_DIR="$agent" \
PI_RENDER_PACKAGE="$render" \
PI_CC_RENDER_PACKAGE="$cc" \
PI_SUBAGENTS_PACKAGE="$subagents" \
  pi --offline --no-extensions --no-skills --no-prompt-templates \
    --no-context-files --no-approve --no-session --mode rpc \
    -e "$PWD/scripts/check-pi-render.ts" </dev/null
