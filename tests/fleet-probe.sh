# A JSON snapshot of what this machine exposes: units, sockets, firewall,
# routing, sysctls, sshd, nix and BPF. Store hashes are blanked, so two
# snapshots of the same config on two nixpkgs revisions differ only where
# versions or behaviour do. Runs as root (the test driver's shell is root).
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

norm() { sed -E 's#/nix/store/[a-z0-9]{32}-#/nix/store/HASH-#g'; }
section() {
  local name=$1
  shift
  { "$@" 2>/dev/null || true; } | norm >"$tmp/$name"
}

# Services restarted three times or more: a restart loop is not "failed" at
# the moment the probe looks. One or two are boot-order races (rex-login-server
# before tailscale has an address), which real hosts have too.
restarting() {
  systemctl list-units --type=service --all --no-legend --plain | awk '{print $1}' \
    | xargs systemctl show -p Id -p NRestarts \
    | awk -v RS= '{ id = ""; n = 0
        for (i = 1; i <= NF; i++) { split($i, a, "="); if (a[1] == "Id") id = a[2]; if (a[1] == "NRestarts") n = a[2] }
        if (n >= 3) print id }' | sort
}

section kernel uname -r
section failed sh -c "systemctl list-units --failed --all --no-legend --plain | awk '{print \$1}' | sort"
# Device, slice and per-session units say nothing about the configuration.
section restarting restarting
section active sh -c "systemctl list-units --state=active --no-legend --plain | awk '{print \$1}' \
  | grep -vE '^(dev-|sys-|run-|session-|user@|user-runtime-dir@)|\\.(device|slice|scope)$' | sort"
section modules sh -c "cut -d' ' -f1 /proc/modules | sort"
# proto, local address, process name: pids and fds change on every boot.
section listen sh -c "ss -Hltunp | awk '{print \$1, \$5, \$7}' | sed -E 's/,pid=[0-9]+,fd=[0-9]+//g' | sort -u"
section nftables sh -c "nft list ruleset | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/'"
section iptables sh -c "{ iptables-save; ip6tables-save; } | sed -E '/^#/d; s/\\[[0-9]+:[0-9]+\\]/[0:0]/'"
section rules sh -c "ip rule show; ip -6 rule show"
section routes sh -c "{ ip route show table all; ip -6 route show table all; } | sed -E 's/ expires [0-9]+sec//' | sort"
# Global and all/default sysctls only: per-interface ones follow which
# interfaces exist, which the probe reports elsewhere.
section sysctl sh -c "sysctl -a | grep -E '^net\\.' \
  | grep -vE '^net\\.ipv[46]\\.(conf|neigh)\\.' | grep -vE 'stable_secret|_random|boot_id|hash_secret' | sort; \
  sysctl -a | grep -E '^net\\.ipv[46]\\.(conf|neigh)\\.(all|default)\\.' | sort"
# The system's own sshd, by absolute path (it refuses to run otherwise). The
# config has Match blocks, so -T needs a connection to evaluate them for.
section sshd sh -c "/run/current-system/sw/bin/sshd -T -C user=root,host=probe,addr=127.0.0.1,lport=22 | sort"
section nix sh -c "nix config show | grep -E '^(substituters|trusted-public-keys|trusted-users|trusted-substituters|experimental-features|sandbox) '"
section bpf sh -c "bpftool prog show | grep -oE 'name [^ ]+' | sort | uniq -c"

out='{}'
for f in "$tmp"/*; do
  out=$(jq --arg k "${f##*/}" --slurpfile v <(jq -R . "$f" | jq -s .) '.[$k] = $v[0]' <<<"$out")
done
printf '%s\n' "$out"
