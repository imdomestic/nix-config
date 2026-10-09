"""Root-only integration test using synthetic devices; never grabs the real pad.

Requires python-evdev. Pass the built vfio-touchpad executable as argv[1].
The physical pad is opened only to clone its capability metadata.
"""

import evdev
import time
import subprocess
import select
import sys
from evdev import ecodes as e

real = evdev.InputDevice(
    "/dev/input/by-path/pci-0000:00:19.0-platform-i2c_designware.3-event-mouse"
)
caps = real.capabilities(absinfo=True)
caps.pop(e.EV_SYN, None)
props = real.input_props()
real.close()
proc = None
out = None
with evdev.UInput(caps, name="VFIO synthetic test touchpad", input_props=props) as pad:
    try:
        subprocess.run(["udevadm", "settle"], check=True)
        proc = subprocess.Popen(
            [sys.argv[1], pad.device.path], stderr=subprocess.PIPE, text=True
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            ready = select.select([proc.stderr], [], [], 0.1)[0]
            if ready:
                line = proc.stderr.readline().strip()
                print(line, flush=True)
                if line.startswith("Relative pointer ready: "):
                    out = evdev.InputDevice(line.split(": ", 1)[1])
                    out.grab()
                    break
            if proc.poll() is not None:
                raise RuntimeError("bridge exited")
        assert out is not None, "no output device"
        assert e.EV_ABS not in out.capabilities(), (
            "output must not expose absolute axes"
        )

        def send(x, y, tracking=None):
            pad.write(e.EV_ABS, e.ABS_MT_SLOT, 0)
            if tracking is not None:
                pad.write(e.EV_ABS, e.ABS_MT_TRACKING_ID, tracking)
                pad.write(e.EV_KEY, e.BTN_TOUCH, int(tracking >= 0))
                pad.write(e.EV_KEY, e.BTN_TOOL_FINGER, int(tracking >= 0))
            if tracking != -1:
                for code, val in [
                    (e.ABS_X, x),
                    (e.ABS_Y, y),
                    (e.ABS_MT_POSITION_X, x),
                    (e.ABS_MT_POSITION_Y, y),
                ]:
                    pad.write(e.EV_ABS, code, val)
            pad.syn()
            time.sleep(0.012)

        def collect():
            found = []
            while select.select([out.fd], [], [], 0.1)[0]:
                found.extend(out.read())
            return found

        axes = dict(caps[e.EV_ABS])
        x = (axes[e.ABS_X].min + axes[e.ABS_X].max) // 2
        y = (axes[e.ABS_Y].min + axes[e.ABS_Y].max) // 2
        send(x, y, 1)
        for i in range(1, 25):
            send(x + i * 5, y)
        send(0, 0, -1)
        time.sleep(0.2)
        moved = collect()
        rel = [v for v in moved if v.type == e.EV_REL]
        assert any(v.code == e.REL_X and v.value > 0 for v in rel), (
            "right swipe produced no relative X"
        )
        assert not any(v.type == e.EV_ABS for v in moved)
        send(x - 250, y, 2)
        time.sleep(0.05)
        send(0, 0, -1)
        time.sleep(0.3)
        lifted = collect()
        assert not any(
            v.type == e.EV_REL and v.code in [e.REL_X, e.REL_Y] for v in lifted
        ), "finger recontact jumped pointer"
        clicks = [(v.code, v.value) for v in lifted if v.type == e.EV_KEY]
        assert (e.BTN_LEFT, 1) in clicks and (e.BTN_LEFT, 0) in clicks, (
            "tap did not click"
        )

        def two_fingers(offset, start=False, end=False):
            pad.write(e.EV_KEY, e.BTN_TOOL_FINGER, 0)
            pad.write(e.EV_KEY, e.BTN_TOOL_DOUBLETAP, int(not end))
            pad.write(e.EV_KEY, e.BTN_TOUCH, int(not end))
            for slot in range(2):
                pad.write(e.EV_ABS, e.ABS_MT_SLOT, slot)
                if start or end:
                    pad.write(e.EV_ABS, e.ABS_MT_TRACKING_ID, -1 if end else slot + 3)
                if not end:
                    pad.write(e.EV_ABS, e.ABS_MT_POSITION_X, x + slot * 100)
                    pad.write(e.EV_ABS, e.ABS_MT_POSITION_Y, y + offset)
            if not end:
                pad.write(e.EV_ABS, e.ABS_X, x)
                pad.write(e.EV_ABS, e.ABS_Y, y + offset)
            pad.syn()
            time.sleep(0.012)

        two_fingers(0, start=True)
        for i in range(1, 25):
            two_fingers(i * 5)
        two_fingers(0, end=True)
        time.sleep(0.2)
        scrolled = collect()
        assert any(
            v.type == e.EV_REL and v.code == e.REL_WHEEL and v.value < 0
            for v in scrolled
        ), "two-finger down scroll missing"
        print(
            "PASS: relative swipe, no absolute axes, no recontact jump, tap click, two-finger scroll",
            flush=True,
        )
    finally:
        if out:
            out.close()
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                raise
            assert proc.returncode == 0, proc.stderr.read()
