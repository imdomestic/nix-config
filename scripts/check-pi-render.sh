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
agent=$(mktemp -d)
trap 'rm -rf "$agent"' EXIT

PI_CODING_AGENT_DIR="$agent" \
PI_RENDER_PACKAGE="$render" \
PI_CC_RENDER_PACKAGE="$cc" \
  pi --offline --no-extensions --no-skills --no-prompt-templates \
    --no-context-files --no-session --mode rpc \
    -e "$PWD/scripts/check-pi-render.ts" </dev/null
