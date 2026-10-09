#!/usr/bin/env bash
# Runs only inside the disposable diagnostic guest; see docs/268v-windows-vfio.md.
set -u
exec >/dev/ttyS0 2>&1
echo VFIO_LINUX_PROBE_BEGIN
uname -a
udevadm settle --timeout=45 || true
sleep 10
lspci -nnk
echo VFIO_LINUX_DRM_DEVICES
ls -l /dev/dri /sys/class/drm || true
for connector in /sys/class/drm/card*-*/status; do
    test -e "$connector" || continue
    printf '%s: ' "$connector"
    cat "$connector"
done
echo VFIO_LINUX_DRM_INFO
timeout 30 drm_info || true
echo VFIO_LINUX_VULKAN
timeout 45 vulkaninfo --summary || true
echo VFIO_LINUX_KERNEL_LOG
dmesg
echo VFIO_LINUX_PROBE_DONE
sync
# Leave the running guest available briefly for the controller's QMP capture.
sleep 30
systemctl poweroff --no-block
