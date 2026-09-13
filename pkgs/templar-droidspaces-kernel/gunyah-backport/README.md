# Gunyah host-VM backport

This tree carries the Android Common Kernel `android14-6.1` Gunyah host VM
userspace ABI into the Templar Android 5.10 GKI build. The imported VM, vCPU,
irqfd, ioeventfd, UAPI and hypercall code is based on ACK commit
`6308d6d3f1b14871eacf2a598b2fa32b93d167b4`.

`rsc_mgr_legacy.c` is the 5.10-specific integration layer. It deliberately does
not bind the Resource Manager device-tree node or open a second message queue.
Instead it resolves and reuses the ROM's already-loaded Qualcomm `gh_rm_drv`
transport, notification chain, IRQ mapping and `secure_buffer` memory assignment
path. All imported internal RM symbols use the `ghh_rm_` prefix so they do not
collide with Qualcomm's legacy exports.

The result is experimental and must first be loaded manually. A successful
module load and creation of `/dev/gunyah` are only the first acceptance gates;
creating, booting and tearing down a non-protected crosvm guest without losing
Android hardware functionality remain required before any boot-time enablement.

The exposed ioctl ABI intentionally stops at the Android 14 / ACK 6.1 baseline.
The Android 17 crosvm currently present on the test phone also knows newer
Android-specific Gunyah ioctls, so the first guest test should use a matching
Android 14 crosvm. Extending the ABI is a separate step after the base path is
proven; unknown ioctls fail with `-ENOTTY` rather than being guessed here.
