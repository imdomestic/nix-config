# system-deploy: brings this host's system to a commit of the repository.
# What is above this line is the host's own, from system-deploy.nix: its
# name, the state directory and the units a switch is judged by.

PATH=$PATH:/run/current-system/sw/bin:/run/wrappers/bin
repo=imdomestic/nix-config
profile=/nix/var/nix/profiles/system
unit=system-deploy-switch
# How long a watched unit has to come up after a switch, and how long its
# new process has to last before it counts as up, in seconds.
patience=180
settle=20

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
# keeps it from the garbage collector until the next build. A build that
# failed at fetching is tried again: GitHub from China drops a fetch now
# and then, and an input or a crate's git source may need one.
build() {
  local try
  for try in 1 2 3 4; do
    if nix build --out-link "$state/target" --print-out-paths \
      "github:$repo/$1#nixosConfigurations.\"$host\".config.system.build.toplevel" 2>"$state/build.log"; then
      return 0
    fi
    if ((try == 4)) || ! grep -qE 'Failed to fetch|unable to access|unable to download|TLS connect error|timed out|Connection reset' "$state/build.log"; then
      return 1
    fi
    sleep 10
  done
}

main_pid() { systemctl show --property=MainPID --value "$1"; }

# What a check says can't be undone, as it is now.
token() {
  if [[ -n ${check_irreversible[$1]} ]]; then
    "${check_irreversible[$1]}" 2>/dev/null || true
  fi
}

# Builds commit $1 and says what a switch to it would do, changing nothing.
# Leaves `running` and `target`. Fails if the build does.
examine() {
  local name line dry deployed_rev="" deployed_path="" none=1
  running=$(readlink -f /run/current-system)
  say commit "$1"
  if [[ -r $state/deployed ]]; then
    read -r deployed_rev deployed_path <"$state/deployed" || true
  fi
  if [[ $deployed_path == "$running" ]]; then
    say running "$running, built from $deployed_rev"
    if [[ $deployed_rev != "$1" ]]; then
      say changes "https://github.com/$repo/compare/$deployed_rev...$1"
    fi
  else
    say running "$running, which system-deploy didn't switch to: someone else did, and its commit isn't known here"
  fi
  if ! target=$(build "$1"); then
    say build "failed; the end of $state/build.log:"
    tail -n 15 "$state/build.log"
    return 1
  fi
  say built "$target"
  if [[ $target == "$running" ]]; then
    say same "this is the system that runs: a switch changes nothing"
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
  if ((none)); then say units "no unit is stopped, started or restarted"; fi
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
      if [[ $pid == "${pid_before[$name]}" ]]; then return 0; fi
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
  local name down=0 deadline=$((SECONDS + patience))
  for name in "${check_names[@]}"; do
    if unit_up "$name" "$deadline"; then
      say "$name" "${check_unit[$name]} is up"
    else
      say "$name" "${check_unit[$name]} isn't up ${patience}s after the switch: $(systemctl is-active "${check_unit[$name]}" || true); journalctl -u ${check_unit[$name]} says why"
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

# The switch ended without a result of its own: a command it rests on failed.
broke_off() {
  say result "failed: the switch broke off before its end; journalctl -u $unit may say where"
  echo failed >"$state/state"
}

# `switch`, in its own unit: all of it goes to the report.
switch_inner() {
  local name pid status=0
  declare -A pid_before=() token_before=()
  rev=$1
  need_root switch
  take_lock
  exec >"$state/report" 2>&1
  echo switching >"$state/state"
  trap broke_off EXIT
  say started "$(date --iso-8601=seconds) on $host"
  if ! examine "$rev"; then finish failed "nothing was switched"; fi
  if [[ $target == "$running" ]]; then
    echo "$rev $target" >"$state/deployed"
    finish ok "$host runs $rev already"
  fi
  for name in "${check_names[@]}"; do
    pid_before[$name]=$(main_pid "${check_unit[$name]}")
    token_before[$name]=$(token "$name")
  done

  nix-env --profile "$profile" --set "$target"
  "$target/bin/switch-to-configuration" switch >"$state/switch.log" 2>&1 || status=$?
  say switched "switch-to-configuration exited $status; what it said is in $state/switch.log"
  if all_up; then
    echo "$rev $target" >"$state/deployed"
    for name in "${check_names[@]}"; do
      if [[ -n ${check_after[$name]} ]]; then
        pid=$(main_pid "${check_unit[$name]}")
        while IFS= read -r line; do
          say "$name" "$line"
        done < <("${check_after[$name]}" "$pid" "${pid_before[$name]}" 2>&1 || true)
      fi
    done
    if ((status != 0)); then
      finish ok "$host runs $rev, though switch-to-configuration exited $status: some unit failed, see switch.log"
    fi
    finish ok "$host runs $rev"
  fi

  for name in "${check_names[@]}"; do
    if [[ $(token "$name") != "${token_before[$name]}" ]]; then
      finish failed "$host is on $rev with a watched unit down, and can't go back by itself: $name changed what the system before can't run on (${token_before[$name]} -> $(token "$name")). Someone has to look"
    fi
  done
  say back "to $running"
  nix-env --profile "$profile" --set "$running"
  status=0
  "$running/bin/switch-to-configuration" switch >>"$state/switch.log" 2>&1 || status=$?
  if all_up; then
    finish rolled-back "$rev was switched to and didn't hold; $host runs the system before again"
  fi
  finish failed "a watched unit is down on $rev and on the system before as well. Someone has to look"
}

status() {
  local running deployed_rev="" deployed_path=""
  running=$(readlink -f /run/current-system)
  if [[ -r $state/deployed ]]; then
    read -r deployed_rev deployed_path <"$state/deployed" || true
  fi
  if [[ $deployed_path == "$running" ]]; then
    echo "$host runs $running, built from $repo $deployed_rev"
  else
    echo "$host runs $running, which system-deploy didn't switch to"
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
    say result "nothing was switched: sudo system-deploy switch $rev does it"
    ;;
  switch)
    need_root switch
    rev=$(resolve "${2:-}")
    if systemctl is-active --quiet "$unit.service"; then
      echo "system-deploy: a switch is going already; system-deploy says how it goes" >&2
      exit 1
    fi
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
