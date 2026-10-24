#!/usr/bin/env bash
# Commit message for an llm-agents bump: which packages changed version, the
# ones this repo uses first. Used by .github/workflows/update-llm-agents.yml.
#
#   scripts/llm-agents-changes.sh <old-rev> <new-rev>   (from the repo root)
set -euo pipefail
old=$1 new=$2

# Every package the repo references as inputs.llm-agents.packages.${…}.<name>,
# skipping commented-out lines.
used=$(grep -rhoE '^[^#]*inputs\.llm-agents\.packages\.\$\{[^}]+\}\.[A-Za-z0-9_-]+' home system hosts \
  | sed -E 's/.*\.//' | sort -u | jq -R . | jq -s .)

# name -> version on both platforms the fleet builds them for; a package that
# fails to evaluate on one counts as absent there.
versions() {
  for sys in x86_64-linux aarch64-darwin; do
    nix eval --json "github:numtide/llm-agents.nix/$1#packages.$sys" --apply '
      ps: builtins.mapAttrs (_: p: let
        v = builtins.tryEval (p.version or "");
      in if v.success then v.value else "") ps'
  done | jq -s 'add'
}
a=$(versions "$old")
b=$(versions "$new")

jq -rn --argjson a "$a" --argjson b "$b" --argjson used "$used" \
  --arg old "${old:0:7}" --arg new "${new:0:7}" '
  def row: "\(.name)  \(.from // "(new)") -> \(.to // "(removed)")";
  def fits: ("flake: update llm-agents: " + .) | length <= 72;
  [($a + $b | keys)[] as $k | select($a[$k] != $b[$k])
    | {name: $k, from: $a[$k], to: $b[$k], used: ($used | index($k) != null)}]
  | (map(select(.used))) as $mine
  | (map(select(.used | not))) as $rest
  | ($mine | map("\(.name) \(.to // "removed")") | join(", ")) as $withVersions
  | ($mine | map(.name) | join(", ")) as $names
  | (if $mine == [] then "flake: update llm-agents (nothing used here changed)"
     elif ($withVersions | fits) then "flake: update llm-agents: " + $withVersions
     elif ($names | fits) then "flake: update llm-agents: " + $names
     else "flake: update llm-agents: \($mine | length) packages used here" end),
    "",
    "numtide/llm-agents.nix \($old) -> \($new), built on x86_64-linux and aarch64-darwin.",
    (if $mine != [] then "", "Used here:", ($mine[] | "  " + row) else empty end),
    (if $rest != [] then "", "Also changed upstream (\($rest | length)): \($rest | map(.name) | join(", "))." else empty end)' \
  | fold -s -w 72 | sed -E 's/ +$//'
