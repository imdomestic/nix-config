#!/usr/bin/env bash
# Run on taipan or tank as a transient service, never on the laptop being rebooted.
set -euo pipefail
export PATH=/run/current-system/sw/bin
controller=$(hostname -s)
case "$controller" in
    taipan|tank) ;;
    *) echo 'Run this controller on taipan or tank, not on 268v.' >&2; exit 1 ;;
esac
out=/var/tmp/268v-vfio-probe
mkdir -p "$out"
exec >>"$out/controller.log" 2>&1
remote() { timeout --kill-after=5 15 tailscale ssh root@268v "$@"; }
log() { printf '%s %s\n' "$(date -Is)" "$*"; }
normal=
vfio=
python=/nix/store/0if41r2dp11y0v833p5yrpgr8mdanqjk-python3-3.13.15-env/bin/python3
rebooted=false
mode=windows
check=false
for arg in "$@"; do
    case "$arg" in
        --linux) mode=linux ;;
        --check) check=true ;;
        *) log "Unknown argument: $arg"; exit 1 ;;
    esac
done
domain=windows11
[[ "$mode" == linux ]] && domain=vfio-linux-probe

capture() {
    local name=$1 command=$2
    if remote "$command" >"$out/$name.partial" 2>/dev/null; then
        mv "$out/$name.partial" "$out/$name"
    fi
}

evidence() {
    capture kernel.log 'journalctl -b -k --no-pager'
    capture qemu.log "cat /var/log/libvirt/qemu/$domain.log"
    if [[ "$mode" == linux ]]; then
        capture linux-serial.log 'cat /var/lib/libvirt/qemu/vfio-linux-probe-serial.log'
    else
        capture guest.json 'cat /var/tmp/268v-vfio-probe/guest.json'
    fi
    capture firmware.json "$python /var/tmp/268v-vfio-probe/firmware.py --domain $domain"
    if remote "virsh -c qemu:///system qemu-monitor-command $domain '{\"execute\":\"screendump\",\"arguments\":{\"filename\":\"/tmp/268v-vfio-screen.png\",\"format\":\"png\"}}'"; then
        capture screen.png 'cat /tmp/268v-vfio-screen.png'
    fi
}

restore() {
    if ! $rebooted; then return; fi
    log 'Collecting evidence and restoring normal boot'
    evidence
    remote "virsh -c qemu:///system shutdown $domain" || true
    local deadline=$((SECONDS + 90))
    while ((SECONDS < deadline)); do
        state=$(remote "virsh -c qemu:///system domstate $domain" 2>/dev/null || true)
        [[ "$state" == 'shut off' || ( "$mode" == linux && -z "$state" ) ]] && break
        sleep 5
    done
    # The normal default remains unchanged; set it once explicitly for this return.
    remote "bootctl set-oneshot $normal && systemctl reboot" || true
    deadline=$((SECONDS + 180))
    while ((SECONDS < deadline)); do
        sleep 5
        current=$(remote 'readlink /run/current-system' 2>/dev/null || true)
        if [[ -n "$current" && "$current" != *268v-vfio* ]]; then
            remote 'systemctl is-active display-manager; lspci -nnk -s 00:02.0' >"$out/restored.txt" 2>&1 || true
            log "Normal system returned; results are in /var/tmp/268v-vfio-probe on $controller"
            return
        fi
    done
    log 'Automatic return was not confirmed. A physical reboot uses the normal default.'
}
trap restore EXIT
trap 'log "Probe failed at line $LINENO"' ERR

if [[ -z ${HOME:-}${XDG_CONFIG_HOME:-} ]]; then
    log 'Missing login environment; start with User=root and SetLoginEnvironment=yes'
    exit 1
fi
log 'Checking SSH and target prerequisites from the service environment'
oldboot=$(remote 'cat /proc/sys/kernel/random/boot_id')
generation=$(remote 'basename "$(readlink /nix/var/nix/profiles/system)"')
[[ "$generation" =~ ^system-([0-9]+)-link$ ]] || { log 'Cannot identify current system generation'; exit 1; }
normal="nixos-generation-${BASH_REMATCH[1]}.conf"
vfio="nixos-generation-${BASH_REMATCH[1]}-specialisation-vfio.conf"
remote "test -f /boot/loader/entries/$normal && test -f /boot/loader/entries/$vfio && test -x $python && test -f /var/tmp/268v-vfio-probe/receiver.py && virsh -c qemu:///system domstate windows11"
remote "grep -Fq \"init=\$(readlink /run/current-system)/init \" /boot/loader/entries/$normal"
if [[ "$mode" == linux ]]; then
    remote 'test -f /var/tmp/268v-vfio-probe/linux-probe/vfio.xml && test ! -s /var/lib/libvirt/qemu/vfio-linux-probe-serial.log'
else
    remote 'test ! -e /var/tmp/268v-vfio-probe/guest.json'
fi
remote 'test -f /var/tmp/268v-vfio-probe/firmware.py'
log "Using $normal and $vfio"
log 'Preflight passed'
$check && exit 0
log 'Probe scheduled; waiting 45 seconds before guest shutdown'
sleep 45
log 'Requesting normal Windows shutdown'
state=$(remote 'virsh -c qemu:///system domstate windows11')
case "$state" in
    running) remote 'virsh -c qemu:///system shutdown windows11' ;;
    'shut off') log 'Windows is already shut down' ;;
    *) log "Unexpected VM state: $state; aborting"; exit 1 ;;
esac
deadline=$((SECONDS + 120))
while ((SECONDS < deadline)); do
    state=$(remote 'virsh -c qemu:///system domstate windows11')
    [[ "$state" == 'shut off' ]] && break
    sleep 5
done
[[ "$state" == 'shut off' ]] || { log 'Guest did not shut down; aborting without reboot'; exit 1; }
log 'Windows stopped; selecting the one-shot VFIO boot entry'
remote "bootctl set-oneshot $vfio"
rebooted=true
log 'Rebooting 268v'
remote 'systemctl reboot' || true
deadline=$((SECONDS + 240))
newboot=
while ((SECONDS < deadline)); do
    sleep 5
    newboot=$(remote 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)
    [[ -n "$newboot" && "$newboot" != "$oldboot" ]] && break
done
[[ -n "$newboot" && "$newboot" != "$oldboot" ]] || { log 'Host did not reconnect'; exit 1; }
log '268v reconnected after reboot; checking GPU binding'
remote 'readlink /run/current-system; cat /proc/cmdline; lspci -nnk -s 00:02.0; systemctl show nixvirt -p Result -p ExecMainStatus' >"$out/host.txt"
remote 'test "$(basename "$(readlink /sys/bus/pci/devices/0000:00:02.0/driver)")" = vfio-pci'
deadline=$((SECONDS + 60))
while ((SECONDS < deadline)); do
    remote 'virsh -c qemu:///system dumpxml --inactive windows11' >"$out/domain.xml"
    grep -q 'hostdev' "$out/domain.xml" && break
    sleep 5
done
grep -q 'hostdev' "$out/domain.xml"
if [[ "$mode" == linux ]]; then
    start='virsh -c qemu:///system create /var/tmp/268v-vfio-probe/linux-probe/vfio.xml'
else
    remote "systemd-run --unit=268v-vfio-receiver --property=RuntimeMaxSec=600 $python /var/tmp/268v-vfio-probe/receiver.py"
    start='virsh -c qemu:///system start windows11'
fi
if ! remote "$start" >"$out/start.txt" 2>&1; then
    log 'VM start failed; restoring normal boot'
    exit 1
fi
capture domain.xml "virsh -c qemu:///system dumpxml $domain"
log "$domain started with passthrough; waiting for diagnostics"
deadline=$((SECONDS + 300))
next_capture=$((SECONDS + 30))
while ((SECONDS < deadline)); do
    if [[ "$mode" == linux ]]; then
        ready="grep -q '^VFIO_LINUX_PROBE_DONE' /var/lib/libvirt/qemu/vfio-linux-probe-serial.log"
    else
        ready='test -s /var/tmp/268v-vfio-probe/guest.json'
    fi
    if remote "$ready"; then
        log "$domain report received"
        exit 0
    fi
    if ((SECONDS >= next_capture)); then
        log 'Saving intermediate evidence'
        evidence
        next_capture=$((SECONDS + 60))
    fi
    sleep 5
done
log 'Report deadline reached (300 seconds plus bounded in-flight evidence capture); restoring'
