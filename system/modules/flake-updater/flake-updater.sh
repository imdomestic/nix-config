# flake-updater: move each input in $inputs on top of main, one commit each;
# keep the longest run of them after which everything that evaluated, built
# and passed its VM test at main still does; push that to main as the
# imdomestic-updater GitHub App, with a check on the last commit describing
# the run. Problems go to one issue, closed again by the next clean run.
#
#   flake-updater run              what the timer runs
#   flake-updater run --no-push    everything but the push, check and issue
#
# The settings above this text come from system/modules/flake-updater.
umask 077
push=1
case "${1:-} ${2:-}" in
  "run ") ;;
  "run --no-push") push= ;;
  *)
    echo "usage: flake-updater run [--no-push]" >&2
    exit 2
    ;;
esac

run_id=$(date -u +%Y%m%dT%H%M%SZ)
work=$state/nix-config
evals=$state/evals
rundir=$state/runs/$run_id
mkdir -p "$evals" "$rundir"
tmpd=$(mktemp -d)
exec > >(tee -a "$rundir/log") 2>&1
start=$(date +%s)
deadline=$((start + budget))

say() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
left() { echo $((deadline - $(date +%s))); }

# --- GitHub, as the App ---------------------------------------------------
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
token=
token_expires=0
gh_token() {
  if (($(date +%s) + 600 < token_expires)); then return 0; fi
  local now header payload jwt inst resp
  now=$(date +%s)
  header=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
  payload=$(printf '{"iat":%d,"exp":%d,"iss":"%s"}' $((now - 60)) $((now + 540)) "$app_client_id" | b64url)
  jwt="$header.$payload.$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$app_key" | b64url)"
  printf 'Authorization: Bearer %s' "$jwt" >"$tmpd/auth"
  inst=$(curl -fsS --retry 3 -H @"$tmpd/auth" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$repo/installation" | jq -r .id)
  resp=$(curl -fsS --retry 3 -X POST -H @"$tmpd/auth" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/app/installations/$inst/access_tokens")
  token=$(jq -r .token <<<"$resp")
  token_expires=$(date -d "$(jq -r .expires_at <<<"$resp")" +%s)
  printf 'Authorization: Bearer %s' "$token" >"$tmpd/auth"
  printf '%s\n' "$token" >"$tmpd/token"
  # nix fetches with the App's token, so GitHub's API limit is the App's,
  # not the anonymous 60 an hour.
  export NIX_CONFIG="access-tokens = github.com=$token"
}
# gh_api METHOD PATH: the request body, if any, comes on stdin.
gh_api() {
  gh_token
  local args=(-fsS --retry 3 -X "$1" -H @"$tmpd/auth"
    -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28")
  if [[ $1 != GET ]]; then args+=(--data-binary @-); fi
  curl "${args[@]}" "https://api.github.com$2"
}

# --- The flake ------------------------------------------------------------
# locked REV INPUT: "2026-11-05 1a2b3c4", what the lock at REV (or, for "",
# the working tree) pins INPUT to.
locked() {
  if [[ -n $1 ]]; then git show "$1:flake.lock"; else cat flake.lock; fi | jq -r --arg i "$2" '
    .nodes[.nodes.root.inputs[$i]].locked
    | ((.lastModified // 0) | strftime("%Y-%m-%d")) + " "
      + (if .rev then .rev[0:7] else (.narHash // "?" | sub("^sha256-"; "") | .[0:8]) end)'
}

# Moves each input given on top of HEAD, one commit each, appending to
# chain_inputs / chain_revs. An input that cannot be fetched is noted and left.
chain_inputs=()
chain_revs=()
declare -A unfetchable=()
extend_chain() {
  local i old new
  for i in "$@"; do
    gh_token
    if ! timeout 600 nix flake update "$i" >"$tmpd/update.err" 2>&1; then
      unfetchable[$i]=$(tail -3 "$tmpd/update.err")
      git checkout -q -- flake.lock
      say "$i: could not update"
      continue
    fi
    if git diff --quiet -- flake.lock; then continue; fi
    old=$(locked HEAD "$i")
    new=$(locked "" "$i")
    git commit -q -m "flake: update $i: $old → $new" -m "Moved by the nightly updater on tank, then built and VM-tested with the
other inputs of the same run; the run is described by the \`nightly update\`
check on its last commit." -- flake.lock
    chain_inputs+=("$i")
    chain_revs+=("$(git rev-parse HEAD)")
    say "$i: $old → $new"
  done
}

ref() { echo "git+file://$work?rev=$1"; }

# evaluate REV: $evals/REV.json, see fleet.nix. The three kinds evaluate side
# by side (about 3, 2.5 and 6 minutes on tank). A kind that does not evaluate
# as a whole is evaluated entry by entry, so one broken host does not hide the
# others.
evaluate() {
  local rev=$1 kind out=$evals/$1.json pids=() p rc=0
  [[ -s $out ]] && return 0
  for kind in nixos darwin home; do
    eval_kind "$rev" "$kind" &
    pids+=("$!")
  done
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  ((rc == 0)) || return 1
  nix eval --impure --json --expr "(import $fleet_nix \"$(ref "$rev")\").tests" >"$tmpd/tests.json" 2>/dev/null ||
    echo '[]' >"$tmpd/tests.json"
  jq -n --slurpfile n "$tmpd/nixos.json" --slurpfile d "$tmpd/darwin.json" \
    --slurpfile h "$tmpd/home.json" --slurpfile t "$tmpd/tests.json" \
    '{nixos: $n[0], darwin: $d[0], home: $h[0], tests: $t[0]}' >"$out"
}
eval_kind() {
  local rev=$1 kind=$2
  if ! nix eval --impure --json --expr "(import $fleet_nix \"$(ref "$rev")\").$kind" \
    >"$tmpd/$kind.json" 2>"$tmpd/$kind.err"; then
    say "${rev:0:12}: $kind does not evaluate as a whole, one at a time"
    eval_each "$rev" "$kind" >"$tmpd/$kind.json"
  fi
}
eval_each() {
  local rev=$1 kind=$2 names n entry each=$tmpd/each-$2
  names=$(nix eval --impure --json --expr "builtins.attrNames (import $fleet_nix \"$(ref "$rev")\").$kind") || return 1
  echo '{}' >"$each.json"
  while read -r n; do
    if ! entry=$(nix eval --impure --json --expr "(import $fleet_nix \"$(ref "$rev")\").$kind.\"$n\"" 2>"$each.err"); then
      entry=$(jq -n --rawfile e "$each.err" '{system: null, drv: null, error: ($e | split("\n") | map(select(test("error:"))) | last // "does not evaluate")}')
    fi
    jq --arg n "$n" --argjson e "$entry" '.[$n] = $e' "$each.json" >"$each.next" && mv "$each.next" "$each.json"
  done < <(jq -r '.[]' <<<"$names")
  cat "$each.json"
}

# why REV KIND NAME: the error that stops NAME evaluating (fleet.nix's tryEval
# only says that it does), from the last "error:" on.
why() {
  nix eval --impure --raw --expr "(import $fleet_nix \"$(ref "$1")\").why.$2 \"$3\"" 2>&1 >/dev/null |
    awk '/^ *error: ./ { buf = "" } { buf = buf $0 "\n" } END { printf "%s", buf }' | head -12
}

# changes A B: every system or home whose drvPath differs between A and B.
changes() {
  jq -n --slurpfile a "$evals/$1.json" --slurpfile b "$evals/$2.json" '
    [ ("nixos", "darwin", "home") as $k
      | ($a[0][$k] + $b[0][$k] | keys[]) as $n
      | {old: $a[0][$k][$n], new: $b[0][$k][$n]}
      | select(.old.drv != .new.drv)
      | {kind: $k, name: $n, system: (.new.system // .old.system), drv: .new.drv,
         olddrv: .old.drv, error: .new.error,
         kernel: [.old.kernel, .new.kernel], nvidia: [.old.nvidia, .new.nvidia]} ]'
}

# --- The gate -------------------------------------------------------------
# Platforms built in this run: this machine's own, and those of each remote
# builder in /etc/nix/machines that answers. One that does not leaves its
# platform evaluated only, instead of failing every build for it.
read -ra platforms <<<"$(nix config show system) $(nix config show extra-platforms)"
while read -r uri systems _; do
  [[ -z $uri || $uri == \#* ]] && continue
  host=${uri#*://}
  host=${host#*@}
  if timeout 10 bash -c 'exec 3<>"/dev/tcp/$0/22"' "$host" 2>/dev/null; then
    IFS=, read -ra builder_platforms <<<"$systems"
    platforms+=("${builder_platforms[@]}")
  else
    say "remote builder $host does not answer; ${systems//,/ } evaluated only"
  fi
done < <(cat /etc/nix/machines 2>/dev/null || true)
buildable=$(printf '%s\n' "${platforms[@]}" | jq -R . | jq -sc .)
out_of_time=

built() {
  local outs
  mapfile -t outs < <(nix-store -q --outputs "$1")
  nix-store --check-validity "${outs[@]}" 2>/dev/null
}

# build_all DIR DRV...: builds every output, retrying what failed once
# (GitHub and the caches drop connections from China now and then).
build_all() {
  local g=$1 attempt d todo failed
  shift
  todo=("$@")
  for attempt in 1 2; do
    if (($(left) < 60)); then
      out_of_time=1
      return 1
    fi
    timeout "$(left)" nix build --no-link --keep-going "${todo[@]/%/^*}" 2>"$g/build.err" || true
    failed=()
    for d in "${todo[@]}"; do built "$d" || failed+=("$d"); done
    if ((${#failed[@]} == 0)); then return 0; fi
    todo=("${failed[@]}")
    say "$attempt: ${#failed[@]} failed to build"
  done
  if (($(left) < 60)); then
    out_of_time=1
    return 1
  fi
  {
    for d in "${todo[@]}"; do
      jq -r --arg d "$d" '.[] | select(.drv == $d) | "- \(.kind) `\(.name)` does not build"' "$g/changes.json"
    done
    grep -oE "builder for '[^']+' failed[^;]*" "$g/build.err" | sort -u | head -5 | while read -r line; do
      d=$(grep -oE "/nix/store/[^']+\.drv" <<<"$line")
      printf '\n`%s`\n\n```\n%s\n```\n' "$line" "$(nix log "$d" 2>/dev/null | tail -25)"
    done
  } >>"$g/problems.md"
  return 1
}

probe_lines() { jq -r 'to_entries[] | .key as $k | .value[] | "\($k): \(.)"' "$1/probe.json" | sort; }

# vm_tests REV DIR: every fleet test whose host changed. A passing test's
# snapshot is compared with main's.
vm_tests() {
  local rev=$1 g=$2 t host out old rc=0
  while read -r t; do
    host=${t#*-}
    jq -e --arg h "$host" 'any(.[]; .kind == "nixos" and .name == $h)' "$g/changes.json" >/dev/null || continue
    if (($(left) < 300)); then
      out_of_time=1
      return 1
    fi
    say "${rev:0:12}: VM test $t"
    if out=$(timeout "$(left)" nix build --no-link --print-out-paths "$(ref "$rev")#fleetTests.x86_64-linux.$t" 2>"$g/$t.err"); then
      printf -- '- `%s` passed' "$t" >>"$g/tests.md"
      if jq -e --arg t "$t" '.tests | index($t)' "$evals/$base.json" >/dev/null &&
        old=$(nix build --no-link --print-out-paths "$(ref "$base")#fleetTests.x86_64-linux.$t" 2>/dev/null); then
        if diff -u <(probe_lines "$old") <(probe_lines "$out") >"$g/$t.diff"; then
          printf '; its snapshot is the same as on main.\n' >>"$g/tests.md"
        else
          printf '; its snapshot differs from main:\n\n```diff\n%s\n```\n' \
            "$(grep -E '^[-+][^-+]' "$g/$t.diff" | head -150)" >>"$g/tests.md"
        fi
      else
        printf '.\n' >>"$g/tests.md"
      fi
    else
      (($(left) < 60)) && out_of_time=1
      printf -- '- VM test `%s` fails:\n\n```\n%s\n```\n' "$t" "$(grep -vE '^(copying|building) ' "$g/$t.err" | tail -30)" >>"$g/problems.md"
      rc=1
    fi
  done < <(jq -r '.tests[]' "$evals/$rev.json")
  return $rc
}

# gate REV: does REV keep everything that evaluated, built and passed at
# main? Remembered per revision; details in $rundir/gate-REV/.
declare -A verdict=()
gate() {
  local rev=$1 g=$rundir/gate-$1 ok=1 drvs
  if [[ -n ${verdict[$rev]:-} ]]; then
    [[ ${verdict[$rev]} == pass ]]
    return
  fi
  mkdir -p "$g"
  gh_token
  : >"$g/problems.md"
  : >"$g/tests.md"
  say "gate ${rev:0:12}: evaluating"
  if ! evaluate "$rev" 2>"$g/eval.err"; then
    printf -- '- the flake does not evaluate:\n\n```\n%s\n```\n' "$(tail -20 "$g/eval.err")" >>"$g/problems.md"
    ok=
  else
    changes "$base" "$rev" >"$g/changes.json"
    while read -r kind name; do
      printf -- '- %s `%s` no longer evaluates:\n\n```\n%s\n```\n' "$kind" "$name" "$(why "$rev" "$kind" "$name")" >>"$g/problems.md"
    done < <(jq -r '.[] | select(.drv == null and .olddrv != null) | "\(.kind) \(.name)"' "$g/changes.json")
    [[ -s $g/problems.md ]] && ok=
  fi
  if [[ -n $ok ]]; then
    mapfile -t drvs < <(jq -r --argjson p "$buildable" \
      '.[] | select(.drv != null and (.system as $s | $p | index($s))) | .drv' "$g/changes.json")
    say "gate ${rev:0:12}: building ${#drvs[@]} changed systems and homes"
    if ((${#drvs[@]})) && ! build_all "$g" "${drvs[@]}"; then ok=; fi
  fi
  if [[ -n $ok ]] && ! vm_tests "$rev" "$g"; then ok=; fi
  if [[ -n $out_of_time ]]; then
    say "gate ${rev:0:12}: out of time"
    return 1
  fi
  verdict[$rev]=$([[ -n $ok ]] && echo pass || echo fail)
  say "gate ${rev:0:12}: ${verdict[$rev]}"
  [[ -n $ok ]]
}

# --- Reporting ------------------------------------------------------------
issue_title="Nightly flake update needs attention"
open_issue() {
  gh_api GET "/repos/$repo/issues?state=open&creator=$(jq -rn --arg b "$bot_login" '$b | @uri')&per_page=100" |
    jq -r --arg t "$issue_title" 'map(select(.title == $t))[0].number // empty'
}
problem() {
  [[ -n $push ]] || return 0
  local n
  n=$(open_issue)
  if [[ -n $n ]]; then
    jq -Rs '{body: .}' "$1" | gh_api POST "/repos/$repo/issues/$n/comments" >/dev/null
  else
    jq -Rs --arg t "$issue_title" '{title: $t, body: .}' "$1" | gh_api POST "/repos/$repo/issues" >/dev/null
  fi
}
all_clear() {
  [[ -n $push ]] || return 0
  local n
  n=$(open_issue)
  [[ -n $n ]] || return 0
  jq -n --arg b "The run of $run_id went through cleanly ($1)." '{body: $b}' |
    gh_api POST "/repos/$repo/issues/$n/comments" >/dev/null
  echo '{"state":"closed","state_reason":"completed"}' | gh_api PATCH "/repos/$repo/issues/$n" >/dev/null
}

finished=
on_exit() {
  local rc=$?
  if [[ -z $finished && $rc != 0 ]]; then
    {
      printf 'The run of %s on tank stopped with exit code %s. The end of its log:\n\n```\n' "$run_id" "$rc"
      tail -40 "$rundir/log"
      printf '```\n'
    } >"$tmpd/crash.md"
    problem "$tmpd/crash.md" || true
  fi
  rm -rf "$tmpd"
}
trap on_exit EXIT

# --- The run --------------------------------------------------------------
say "run $run_id, budget $((budget / 60)) min, push: ${push:-no}"
if [[ ! -d $work/.git ]]; then git clone -q "https://github.com/$repo.git" "$work"; fi
cd "$work"
git fetch -q origin main
git checkout -q -B nightly origin/main
git reset -q --hard origin/main
git clean -qfdx
git config user.name "$bot_login"
git config user.email "$bot_email"
base=$(git rev-parse HEAD)
say "main is ${base:0:12}"

extend_chain "${inputs[@]}"
if ((${#chain_inputs[@]} == 0)); then
  say "nothing to update"
  finished=1
  exit 0
fi

say "evaluating main"
if ! evaluate "$base" 2>"$rundir/base-eval.err"; then
  printf 'main (%s) itself does not evaluate on tank, so nothing was tested:\n\n```\n%s\n```\n' \
    "$base" "$(tail -20 "$rundir/base-eval.err")" >"$tmpd/base.md"
  problem "$tmpd/base.md"
  finished=1
  exit 1
fi

# Find the longest run of inputs that passes: try them all, and if that fails
# bisect for the first one that breaks the gate, drop it, re-apply the rest.
declare -A dropped=()
good=$base
while ((${#chain_revs[@]})); do
  n=${#chain_revs[@]}
  if gate "${chain_revs[n - 1]}"; then
    good=${chain_revs[n - 1]}
    break
  fi
  [[ -n $out_of_time ]] && break
  lo=0
  hi=$n
  while ((hi - lo > 1)); do
    mid=$(((lo + hi) / 2))
    if gate "${chain_revs[mid - 1]}"; then lo=$mid; else
      if [[ -n $out_of_time ]]; then
        if ((lo > 0)); then good=${chain_revs[lo - 1]}; fi
        break 2
      fi
      hi=$mid
    fi
  done
  bad=$((hi - 1))
  dropped[${chain_inputs[bad]}]=$rundir/gate-${chain_revs[bad]}/problems.md
  say "dropping ${chain_inputs[bad]}"
  if ((bad > 0)); then good=${chain_revs[bad - 1]}; else good=$base; fi
  rest=("${chain_inputs[@]:hi}")
  git reset -q --hard "$good"
  chain_inputs=("${chain_inputs[@]:0:bad}")
  chain_revs=("${chain_revs[@]:0:bad}")
  extend_chain "${rest[@]}"
done
if [[ -n $out_of_time ]]; then say "out of time; keeping what passed"; fi

# What gets pushed: main..good.
mapfile -t kept < <(git log --reverse --format=%s "$base..$good" | sed -E 's/^flake: update ([^:]+):.*/\1/')
report=$rundir/report.md
{
  printf 'Base: `%s`. ' "${base:0:12}"
  if ((${#kept[@]})); then printf 'Updated %s input(s).\n\n' "${#kept[@]}"; else printf 'Nothing passed.\n\n'; fi
  if ((${#kept[@]})); then
    printf '| Input | From | To |\n|---|---|---|\n'
    for i in "${kept[@]}"; do printf '| `%s` | %s | %s |\n' "$i" "$(locked "$base" "$i")" "$(locked "$good" "$i")"; done
    printf '\n'
  fi
  if ((${#dropped[@]})); then
    printf '## Left out\n\n'
    for i in "${!dropped[@]}"; do printf '### `%s`\n\n%s\n\n' "$i" "$(cat "${dropped[$i]}")"; done
  fi
  if ((${#unfetchable[@]})); then
    printf '## Could not be fetched\n\n'
    for i in "${!unfetchable[@]}"; do printf -- '- `%s`: %s\n' "$i" "$(tr '\n' ' ' <<<"${unfetchable[$i]}")"; done
    printf '\n'
  fi
  if [[ -n $out_of_time ]]; then printf '## Out of time\n\nThe run hit its %s-minute budget; inputs after the last passing one were not tried.\n\n' "$((budget / 60))"; fi
  if [[ $good != "$base" ]]; then
    g=$rundir/gate-$good
    printf '## What changed\n\n'
    jq -r 'group_by(.kind)[] | "- \(.[0].kind): " + (map("`\(.name)`") | join(", "))' "$g/changes.json"
    printf '\n'
    jq -r '.[] | select(.kind == "nixos" and (.kernel[0] != .kernel[1] or .nvidia[0] != .nvidia[1]))
      | "- `\(.name)`: "
        + ([ (if .kernel[0] != .kernel[1] then "kernel \(.kernel[0]) → \(.kernel[1])" else empty end),
             (if .nvidia[0] != .nvidia[1] then "nvidia \(.nvidia[0]) → \(.nvidia[1])" else empty end) ] | join(", "))
        + ": deploy with `--boot`, then reboot"' "$g/changes.json" >"$tmpd/reboots"
    if [[ -s $tmpd/reboots ]]; then printf '## Needs a reboot\n\n%s\n\n' "$(cat "$tmpd/reboots")"; fi
    if [[ -s $g/tests.md ]]; then printf '## VM tests\n\n%s\n\n' "$(cat "$g/tests.md")"; fi
    jq -r '.[] | select(.drv != null) | .system' "$g/changes.json" | sort -u | while read -r s; do
      jq -e --arg s "$s" 'index($s)' <<<"$buildable" >/dev/null ||
        printf -- '- %s: evaluated only, CI dry-builds it after the push\n' "$s"
    done >"$tmpd/unbuilt"
    if [[ -s $tmpd/unbuilt ]]; then printf '## Not built here\n\n%s\n' "$(cat "$tmpd/unbuilt")"; fi
  fi
} >"$report"

problems=
if ((${#dropped[@]} + ${#unfetchable[@]})) || [[ -n $out_of_time ]]; then problems=1; fi

if [[ $good == "$base" ]]; then
  say "nothing passed"
  cat "$report"
  problem "$report"
  finished=1
  exit 1
fi

git reset -q --hard "$good"
if [[ -z $push ]]; then
  say "not pushing (--no-push); would push ${#kept[@]} commit(s)"
  cat "$report"
  finished=1
  exit 0
fi

# main may have moved (the hourly llm-agents bump); those commits were not
# tested with ours, but they only touch their own input.
git fetch -q origin main
if [[ $(git rev-parse origin/main) != "$base" ]]; then
  say "main moved to $(git rev-parse --short origin/main); rebasing"
  if ! git rebase -q origin/main; then
    git rebase --abort
    printf '%s\n\nmain moved during the run and the update no longer applies on top of it; nothing was pushed.\n' \
      "$(cat "$report")" >"$tmpd/conflict.md"
    problem "$tmpd/conflict.md"
    finished=1
    exit 1
  fi
fi
cat >"$tmpd/askpass" <<EOF
#!/bin/sh
exec cat "$tmpd/token"
EOF
chmod 700 "$tmpd/askpass"
gh_token
GIT_ASKPASS=$tmpd/askpass git push -q "https://x-access-token@github.com/$repo.git" HEAD:main
pushed=$(git rev-parse HEAD)
say "pushed ${pushed:0:12}"

conclusion=success
if [[ -n $problems ]]; then conclusion=neutral; fi
jq -n --arg sha "$pushed" --arg c "$conclusion" --arg t "Updated ${#kept[@]} input(s)" --rawfile s "$report" \
  '{name: "nightly update", head_sha: $sha, status: "completed", conclusion: $c,
    output: {title: $t, summary: ($s | .[0:65000])}}' | gh_api POST "/repos/$repo/check-runs" >/dev/null
if [[ -n $problems ]]; then problem "$report"; else all_clear "$pushed"; fi
cat "$report"
finished=1
