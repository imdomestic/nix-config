# system-deploy: brings this host's system to a commit of the repository.
# What is above this line is the host's own, from system-deploy.nix: its
# name and the state directory.

PATH=$PATH:/run/current-system/sw/bin:/run/wrappers/bin
repo=imdomestic/nix-config
profile=/nix/var/nix/profiles/system
unit=system-deploy-switch
# How long a watched unit has to come up after a switch, and how long its
# new process has to last before it counts as up, in seconds.
patience=180
settle=20

# The units a switch is judged by, of the system `load_checks` read last.
check_names=()
declare -A check_unit=() check_ready=() check_before=() check_after=() check_irreversible=()
# The process each watched unit had before the switch, by unit.
declare -A pid_before=()

usage() {
  cat >&2 <<'EOF'
usage: system-deploy [status]      what this host runs, and how the last switch went
       system-deploy build [REV]   build REV's system for this host; prints its path
       system-deploy check [REV]   build it, and say what switching to it would do
       system-deploy switch [REV]  build, check and switch, in a unit of its own; goes
                                   back if a watched unit doesn't come up
       system-deploy wait          wait for the switch that is going; shows its report
REV is a full commit id of github.com/imdomestic/nix-config; without one, main's.
EOF
  exit 2
}

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "system-deploy $1: needs root (sudo system-deploy $1)" >&2
    exit 1
  fi
  mkdir -p "$state"
  # Root's own, not the caller's: under sudo nix would leave root's files in
  # their home, and root's cache has what earlier builds fetched.
  export HOME=/root
  unset XDG_CACHE_HOME XDG_CONFIG_HOME XDG_STATE_HOME XDG_DATA_HOME
}

# One build, check or switch at a time: they share the state directory.
take_lock() {
  exec 9>"$state/lock"
  if ! flock -n 9; then
    echo "system-deploy: a build, check or switch is going already; system-deploy says how the switch goes" >&2
    exit 1
  fi
}

# Reads the checks of the system at $1: each system says itself which
# units it is judged by, so a commit that adds, drops or changes a check is
# judged by its own. A system from before this tool has none.
load_checks() {
  check_names=()
  check_unit=() check_ready=() check_before=() check_after=() check_irreversible=()
  if [[ -r $1/etc/system-deploy/checks ]]; then
    # shellcheck source=/dev/null
    source "$1/etc/system-deploy/checks"
  fi
}

# Notes the process of every unit the loaded checks watch.
note_pids() {
  local name
  for name in "${check_names[@]}"; do
    pid_before[${check_unit[$name]}]=$(main_pid "${check_unit[$name]}")
  done
}

# A line of the report.
say() { printf '%-10s %s\n' "$1" "$2"; }

# The commit to deploy: the one given, or main's.
resolve() {
  local rev=${1:-}
  if [[ -z $rev ]]; then
    # GitHub from China drops a fetch now and then.
    for _ in 1 2 3; do
      rev=$(timeout 60 git ls-remote "https://github.com/$repo" refs/heads/main | cut -f1) || rev=
      if [[ -n $rev ]]; then break; fi
      sleep 5
    done
  fi
  if ! [[ $rev =~ ^[0-9a-f]{40}$ ]]; then
    echo "system-deploy: no commit to deploy: main on github.com/$repo didn't resolve, or REV isn't a full commit id" >&2
    exit 1
  fi
  echo "$rev"
}

# Builds this host's system at commit $1 and prints its path; the link
# keeps it from the garbage collector until the next build. `built` keeps
# which commit every system came from, for `commit_of`. A build that
# failed at fetching is tried again: GitHub from China drops a fetch now
# and then, and an input or a crate's git source may need one. A commit
# GitHub doesn't have stays missing.
build() {
  local try out
  for try in 1 2 3 4; do
    if out=$(nix build --out-link "$state/target" --print-out-paths \
      "github:$repo/$1#nixosConfigurations.\"$host\".config.system.build.toplevel" 2>"$state/build.log"); then
      if ! grep -qxF "$1 $out" "$state/built" 2>/dev/null; then echo "$1 $out" >>"$state/built"; fi
      echo "$out"
      return 0
    fi
    if ((try == 4)) || grep -q 'HTTP error 404' "$state/build.log" ||
      ! grep -qE 'Failed to fetch|unable to access|unable to download|TLS connect error|timed out|Connection reset' "$state/build.log"; then
      return 1
    fi
    sleep 10
  done
}

# The commit the system at $1 was built from, if it was built here: the
# last one, where two commits give the same system.
commit_of() {
  { grep -F " $1" "$state/built" 2>/dev/null || true; } | tail -n 1 | cut -d" " -f1
}

main_pid() { systemctl show --property=MainPID --value "$1"; }

# What a check says can't be undone, as it is now.
token() {
  if [[ -n ${check_irreversible[$1]} ]]; then
    "${check_irreversible[$1]}" 2>/dev/null || true
  fi
}

# Builds commit $1 and says what a switch to it would do, changing nothing.
# Leaves `running` and `target`, and the target's checks loaded. Fails if
# the build does.
examine() {
  local name line dry from none=1
  running=$(readlink -f /run/current-system)
  from=$(commit_of "$running")
  say commit "$1"
  if [[ -n $from ]]; then
    say running "$running, built from $from"
    if [[ $from != "$1" ]]; then
      say changes "https://github.com/$repo/compare/$from...$1"
    fi
  else
    say running "$running, which system-deploy didn't build: its commit isn't known here"
  fi
  if ! target=$(build "$1"); then
    say build "failed; the end of $state/build.log:"
    tail -n 15 "$state/build.log"
    return 1
  fi
  say built "$target"
  load_checks "$target"
  if [[ $target == "$running" ]]; then
    say same "this is the system that runs: a switch activates it again, which starts what should run and doesn't"
    return 0
  fi
  while IFS= read -r line; do
    say closure "$line"
  done < <(nix store diff-closures "$running" "$target" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' || true)
  if [[ $(readlink -f "$running/kernel") != "$(readlink -f "$target/kernel")" ]]; then
    say kernel "changes: a switch leaves the old one running until a reboot"
  fi
  dry=$("$target/bin/switch-to-configuration" dry-activate 2>&1 || true)
  while IFS= read -r line; do
    none=0
    say units "would ${line#would }"
  done < <(grep -E '^would ' <<<"$dry" | grep -v 'would activate the configuration' || true)
  if ((none)); then say units "no unit that runs is stopped, reloaded or restarted"; fi
  for name in "${check_names[@]}"; do
    if [[ -n ${check_before[$name]} ]]; then
      while IFS= read -r line; do
        say "$name" "$line"
      done < <("${check_before[$name]}" "$running" "$target" 2>&1 || true)
    fi
  done
}

# A watched unit is up: active, and either the process the switch left
# running, or a new one that has lasted `settle` seconds and logged what
# the check calls ready.
unit_up() {
  local name=$1 deadline=$2 pid log seen=0 since=0
  local service=${check_unit[$1]} ready=${check_ready[$1]}
  while ((SECONDS < deadline)); do
    pid=$(main_pid "$service")
    if [[ $pid != 0 && $(systemctl is-active "$service" || true) == active ]]; then
      if [[ $pid == "${pid_before[$service]:-0}" ]]; then return 0; fi
      if [[ $pid != "$seen" ]]; then
        seen=$pid
        since=$SECONDS
      fi
      if ((SECONDS - since >= settle)); then
        if [[ -z $ready ]]; then return 0; fi
        log=$(journalctl _SYSTEMD_UNIT="$service" _PID="$pid" --no-pager --output=cat || true)
        if grep -qE -- "$ready" <<<"$log"; then return 0; fi
      fi
    fi
    sleep 2
  done
  return 1
}

# Every watched unit is up within `patience`; says which isn't.
all_up() {
  local name logged down=0 deadline=$((SECONDS + patience))
  for name in "${check_names[@]}"; do
    if unit_up "$name" "$deadline"; then
      say "$name" "${check_unit[$name]} is up"
    else
      logged=""
      if [[ -n ${check_ready[$name]} ]]; then logged=" that logged \"${check_ready[$name]}\""; fi
      say "$name" "${check_unit[$name]} isn't up ${patience}s after the switch: it is $(systemctl is-active "${check_unit[$name]}" || true), and up is active with one process for ${settle}s$logged; journalctl -u ${check_unit[$name]} says why"
      down=1
    fi
  done
  return "$down"
}

finish() {
  say result "$1: $2"
  echo "$1" >"$state/state"
  printf '%s %s %s\n' "$(date --iso-8601=seconds)" "$rev" "$1" >>"$state/history"
  trap - EXIT
  if [[ $1 == ok ]]; then exit 0; fi
  exit 1
}

# The switch ended without a result of its own: it was stopped, or a
# command it rests on failed. `stage` is where.
broke_off() {
  say result "failed: the switch broke off $stage; journalctl -u $unit may say why"
  echo failed >"$state/state"
  printf '%s %s %s\n' "$(date --iso-8601=seconds)" "$rev" failed >>"$state/history"
}

# `switch`, in its own unit: all of it goes to the report.
switch_inner() {
  local name pid status=0
  declare -A token_before=()
  rev=$1
  need_root switch
  exec >"$state/report" 2>&1
  echo switching >"$state/state"
  stage="before anything was switched"
  trap broke_off EXIT
  say started "$(date --iso-8601=seconds) on $host"
  exec 9>"$state/lock"
  if ! flock -n 9; then finish failed "a build or check was going; nothing was switched"; fi
  if ! examine "$rev"; then finish failed "nothing was switched"; fi
  # The system that runs is judged by its own checks if the host goes back
  # to it, so its units' processes are noted as well.
  load_checks "$running"
  note_pids
  load_checks "$target"
  note_pids
  for name in "${check_names[@]}"; do
    token_before[$name]=$(token "$name")
  done

  # A system that runs already is activated again all the same: a switch to
  # it that broke off may have left its units stopped.
  stage="in the middle of activating $rev: units it stopped may be down, and sudo system-deploy switch $rev activates it again"
  nix-env --profile "$profile" --set "$target"
  "$target/bin/switch-to-configuration" switch >"$state/switch.log" 2>&1 || status=$?
  stage="while it waited for the watched units on $rev, which the host runs"
  say switched "switch-to-configuration exited $status; what it said is in $state/switch.log"
  if all_up; then
    for name in "${check_names[@]}"; do
      if [[ -n ${check_after[$name]} ]]; then
        pid=$(main_pid "${check_unit[$name]}")
        while IFS= read -r line; do
          say "$name" "$line"
        done < <("${check_after[$name]}" "$pid" "${pid_before[${check_unit[$name]}]}" 2>&1 || true)
      fi
    done
    if ((status != 0)); then
      finish ok "$host runs $rev, though switch-to-configuration exited $status: some unit failed, see switch.log"
    fi
    finish ok "$host runs $rev"
  fi

  if [[ $target == "$running" ]]; then
    finish failed "a watched unit is down on $rev, which ran before this switch as well: there is no system before it to go back to. Someone has to look"
  fi
  for name in "${check_names[@]}"; do
    if [[ $(token "$name") != "${token_before[$name]}" ]]; then
      finish failed "$host is on $rev with a watched unit down, and can't go back by itself: $name changed what the system before can't run on (${token_before[$name]} -> $(token "$name")). Someone has to look"
    fi
  done
  say back "to $running"
  load_checks "$running"
  stage="in the middle of going back from $rev to the system before: units may be down, and someone has to look"
  nix-env --profile "$profile" --set "$running"
  status=0
  "$running/bin/switch-to-configuration" switch >>"$state/switch.log" 2>&1 || status=$?
  stage="while it waited for the watched units on the system before $rev, which the host runs again"
  say switched "switch-to-configuration exited $status"
  if all_up; then
    finish rolled-back "$rev was switched to and didn't hold; $host runs the system before again"
  fi
  finish failed "a watched unit is down on $rev and on the system before as well. Someone has to look"
}

status() {
  local running from
  running=$(readlink -f /run/current-system)
  from=$(commit_of "$running")
  if [[ -n $from ]]; then
    echo "$host runs $running, built from $repo $from"
  else
    echo "$host runs $running, which system-deploy didn't build: its commit isn't known here"
  fi
  if systemctl is-active --quiet "$unit.service"; then
    echo "a switch is going; its report so far:"
  elif [[ -r $state/report ]]; then
    echo "the last switch:"
  fi
  if [[ -r $state/report ]]; then cat "$state/report"; fi
}

case "${1:-status}" in
  status)
    status
    ;;
  build)
    need_root build
    take_lock
    rev=$(resolve "${2:-}")
    if ! build "$rev"; then
      tail -n 15 "$state/build.log" >&2
      exit 1
    fi
    ;;
  check)
    need_root check
    take_lock
    rev=$(resolve "${2:-}")
    if ! examine "$rev"; then exit 1; fi
    if [[ $target != "$running" ]]; then
      say result "nothing was switched: sudo system-deploy switch $rev does it"
    fi
    ;;
  switch)
    need_root switch
    rev=$(resolve "${2:-}")
    if systemctl is-active --quiet "$unit.service"; then
      echo "system-deploy: a switch is going already; system-deploy says how it goes" >&2
      exit 1
    fi
    take_lock
    exec 9>&-
    systemd-run --unit="$unit" --collect --quiet --service-type=exec \
      --description="system-deploy switch $rev" --setenv=PATH="$PATH" "$0" _switch "$rev"
    echo "started for $rev, in $unit.service: it goes on whatever becomes of this shell."
    echo "system-deploy wait follows it to its end; system-deploy shows the report."
    ;;
  _switch)
    switch_inner "$2"
    ;;
  wait)
    while systemctl is-active --quiet "$unit.service"; do sleep 3; done
    status
    if [[ $(cat "$state/state" 2>/dev/null || true) != ok ]]; then exit 1; fi
    ;;
  *)
    usage
    ;;
esac
