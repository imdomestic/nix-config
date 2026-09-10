"""Read-only NVIDIA supplements; atomic node_exporter textfiles, no dependencies."""

import argparse
from collections import Counter
import ctypes
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET


UNITS = {
    "": ("count", 1), "C": ("celsius", 1), "%": ("ratio", 0.01),
    "W": ("watts", 1), "mW": ("watts", 0.001),
    "MHz": ("hertz", 1e6), "GHz": ("hertz", 1e9),
    "MiB": ("bytes", 2**20), "GiB": ("bytes", 2**30),
    "MB": ("bytes", 2**20), "KB/s": ("bytes_per_second", 1024),
    "us": ("seconds", 1e-6), "ms": ("seconds", 0.001),
    "s": ("seconds", 1), "x": ("lanes", 1),
}
STATES = {"Enabled": 1, "Disabled": 0, "Active": 1, "Not Active": 0,
          "Yes": 1, "No": 0}
UNAVAILABLE = {"", "N/A", "[N/A]", "Not Supported", "[Not Supported]"}


def uuid_key(value):
    return value.lower().removeprefix("gpu-")


def number(text):
    if text in STATES:
        return STATES[text], "boolean"
    if re.fullmatch(r"P\d+", text):
        return int(text[1:]), "state"
    match = re.fullmatch(r"([-+]?\d+(?:\.\d+)?)\s*([A-Za-z%/]*|x)", text)
    if match and match[2] in UNITS:
        unit, scale = UNITS[match[2]]
        return float(match[1]) * scale, unit
    return None


class Metrics:
    def __init__(self):
        self.lines = []
        self.types = set()

    def add(self, name, value, labels=None, kind="gauge"):
        if name not in self.types:
            self.lines.extend([f"# HELP {name} NVIDIA telemetry: {name}.",
                               f"# TYPE {name} {kind}"])
            self.types.add(name)
        def quote(value):
            return '"' + str(value).replace('\\', '\\\\').replace('\n', '\\n').replace('"', '\\"') + '"'

        tags = ",".join(f"{k}={quote(v)}"
                        for k, v in sorted((labels or {}).items()))
        self.lines.append(f"{name}" + ("{" + tags + "}" if tags else "") + f" {value}")

    def render(self):
        return "\n".join(self.lines) + "\n"


def leaves(element, prefix=""):
    counts = Counter(child.tag for child in element)
    seen = Counter()
    for child in element:
        suffix = f"[{seen[child.tag]}]" if counts[child.tag] > 1 else ""
        seen[child.tag] += 1
        path = f"{prefix}{child.tag}{suffix}"
        if len(child):
            yield from leaves(child, path + "/")
        else:
            yield path, (child.text or "").strip()


def parse_xml(xml, settings, metrics):
    root = ET.fromstring(xml)
    if root.tag != "nvidia_smi_log":
        raise ValueError("unexpected nvidia-smi XML root")
    selected = {uuid_key(u) for u in settings["uuids"]}
    devices = {}
    for index, gpu in enumerate(root.findall("gpu")):
        uuid = uuid_key(gpu.findtext("uuid", ""))
        if not uuid:
            raise ValueError("GPU is missing its UUID")
        if selected and uuid not in selected:
            continue
        labels = {"uuid": uuid}
        devices[index] = {"uuid": uuid, "pci_bus_id": gpu.attrib["id"].lower()}
        metrics.add("nvidia_gpu_present", 1, labels)
        metrics.add("nvidia_gpu_device_info", 1, labels | {
            "name": gpu.findtext("product_name", "unknown"),
            "pci_bus_id": gpu.attrib["id"].lower(), "index": index,
            "driver_version": root.findtext("driver_version", "unknown"),
            "cuda_version": root.findtext("cuda_version", "unknown"),
        })
        for name, key, scale in [
            ("temperature_warning_celsius", "temperatureWarning", 1),
            ("temperature_critical_celsius", "temperatureCritical", 1),
            ("memory_free_warning_bytes", "memoryFreeWarningMiB", 2**20),
        ]:
            metrics.add("nvidia_gpu_" + name, settings[key] * scale, labels)

        # The legal clock catalogue is static; retain each memory bin's range/count.
        for clocks in gpu.findall("supported_clocks/supported_mem_clock"):
            mem = number(clocks.findtext("value", ""))
            graphics = [number(e.text or "") for e in clocks.findall("supported_graphics_clock")]
            graphics = [n[0] for n in graphics if n]
            if mem and graphics:
                tags = labels | {"memory_clock_hertz": mem[0]}
                for name, value in [("bin_size", len(graphics)), ("min_hertz", min(graphics)),
                                    ("max_hertz", max(graphics))]:
                    metrics.add("nvidia_gpu_supported_graphics_clocks_" + name, value, tags)
        for child in list(gpu):
            if child.tag in {"processes", "supported_clocks"}:
                gpu.remove(child)
        for field, value in leaves(gpu):
            tags = labels | {"field": field}
            available = value not in UNAVAILABLE and "deprecated" not in value.lower()
            metrics.add("nvidia_gpu_field_available", int(available), tags)
            if not available:
                continue
            parsed = number(value)
            if parsed:
                amount, unit = parsed
                metrics.add("nvidia_gpu_detail_value", amount, tags | {"unit": unit})
            else:
                metrics.add("nvidia_gpu_field_info", 1, tags | {"value": value[:200]})

    for uuid in selected:
        metrics.add("nvidia_gpu_expected", 1, {"uuid": uuid})
    return devices


def parse_processes(xml, devices, metrics):
    for index, gpu in enumerate(ET.fromstring(xml).findall("gpu")):
        if index not in devices:
            continue
        uuid = devices[index]["uuid"]
        processes = gpu.findall("processes/process_info")
        metrics.add("nvidia_gpu_processes", len(processes), {"uuid": uuid})
        for process in processes:
            labels = {"uuid": uuid, "pid": process.findtext("pid", "unknown"),
                      "process": os.path.basename(process.findtext("process_name", "unknown"))[:128],
                      "type": process.findtext("type", "unknown"),
                      "gpu_instance_id": process.findtext("gpu_instance_id", "N/A"),
                      "compute_instance_id": process.findtext("compute_instance_id", "N/A")}
            metrics.add("nvidia_gpu_process_info", 1, labels)
            memory = number(process.findtext("used_memory", "N/A"))
            if memory:
                metrics.add("nvidia_gpu_process_memory_bytes", memory[0], labels)


def parse_pmon(output, devices, metrics):
    columns = None
    for line in output.splitlines():
        if line.startswith("# gpu"):
            columns = line.lstrip("# ").split()
        if line.startswith("#") or not line.strip():
            continue
        if not columns:
            raise ValueError("pmon header missing")
        row = dict(zip(columns, line.split(maxsplit=len(columns) - 1)))
        if row.get("pid", "-") == "-" or int(row["gpu"]) not in devices:
            continue
        labels = {"uuid": devices[int(row["gpu"])]["uuid"], "pid": row["pid"],
                  "process": os.path.basename(row.get("command", "unknown"))[:128],
                  "type": row["type"]}
        for field in ("sm", "mem", "enc", "dec", "jpg", "ofa"):
            if row.get(field, "-") != "-":
                metrics.add("nvidia_gpu_process_utilization_ratio", float(row[field]) / 100,
                            labels | {"engine": field})
    if columns is None:
        raise ValueError("pmon is unavailable")


class FanSpeed(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint), ("fan", ctypes.c_uint), ("speed", ctypes.c_uint)]


def nvml_metrics(devices, metrics):
    nvml = ctypes.CDLL("/run/opengl-driver/lib/libnvidia-ml.so.1")
    if nvml.nvmlInit_v2() != 0:
        raise RuntimeError("NVML initialization failed")
    try:
        for device in devices.values():
            handle = ctypes.c_void_p()
            uuid = device["uuid"]
            rc = nvml.nvmlDeviceGetHandleByUUID(("GPU-" + uuid).encode(), ctypes.byref(handle))
            if rc != 0:
                raise RuntimeError(f"NVML UUID lookup failed: {rc}")
            value = ctypes.c_ulonglong()
            rc = nvml.nvmlDeviceGetTotalEnergyConsumption(handle, ctypes.byref(value))
            metrics.add("nvidia_gpu_field_available", int(rc == 0),
                        {"uuid": uuid, "field": "nvml/total_energy"})
            if rc == 0:
                metrics.add("nvidia_gpu_energy_joules_total", value.value / 1000,
                            {"uuid": uuid}, kind="counter")
            elif rc != 3:  # NVML_ERROR_NOT_SUPPORTED is a capability, not a zero reading.
                raise RuntimeError(f"NVML energy query failed: {rc}")
            fans = ctypes.c_uint()
            rc = nvml.nvmlDeviceGetNumFans(handle, ctypes.byref(fans))
            metrics.add("nvidia_gpu_field_available", int(rc == 0),
                        {"uuid": uuid, "field": "nvml/fans"})
            if rc not in (0, 3):
                raise RuntimeError(f"NVML fan count failed: {rc}")
            if rc == 0:
                metrics.add("nvidia_gpu_fans", fans.value, {"uuid": uuid})
            for fan in range(fans.value if rc == 0 else 0):
                speed = ctypes.c_uint()
                rc = nvml.nvmlDeviceGetFanSpeed_v2(handle, fan, ctypes.byref(speed))
                metrics.add("nvidia_gpu_field_available", int(rc == 0),
                            {"uuid": uuid, "field": f"nvml/fan_{fan}/speed_ratio"})
                if rc == 0:
                    metrics.add("nvidia_gpu_fan_speed_ratio", speed.value / 100,
                                {"uuid": uuid, "fan": fan})
                elif rc != 3:
                    raise RuntimeError(f"NVML fan speed failed: {rc}")
                rpm = FanSpeed(ctypes.sizeof(FanSpeed) | (1 << 24), fan, 0)
                rc = nvml.nvmlDeviceGetFanSpeedRPM(handle, ctypes.byref(rpm)) if hasattr(nvml, "nvmlDeviceGetFanSpeedRPM") else 3
                metrics.add("nvidia_gpu_field_available", int(rc == 0),
                            {"uuid": uuid, "field": f"nvml/fan_{fan}/speed_rpm"})
                if rc == 0:
                    metrics.add("nvidia_gpu_fan_intended_speed_rpm", rpm.speed,
                                {"uuid": uuid, "fan": fan})
                elif rc != 3:
                    raise RuntimeError(f"NVML fan RPM failed: {rc}")
    finally:
        nvml.nvmlShutdown()


def command(args, timeout=5):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout).stdout


def pci_key(value):
    domain, bus, slot = value.lower().split(":")
    return f"{int(domain, 16):04x}:{bus}:{slot.split('.')[0]}"


def parse_journal(output, state, devices):
    buses = {pci_key(d["pci_bus_id"]): d["uuid"] for d in devices.values()}
    state.setdefault("buses", {}).update(buses)
    cutoff = state.get("last_journal_usec", 0)
    for line in output.splitlines():
        entry = json.loads(line)
        stamp_usec = int(entry["__REALTIME_TIMESTAMP"])
        if stamp_usec <= cutoff:
            continue
        match = re.search(r"NVRM: Xid \(PCI:([0-9a-fA-F:.]+)\):\s*(\d+)", entry.get("MESSAGE", ""))
        if match and pci_key(match[1]) in state["buses"]:
            key = state["buses"][pci_key(match[1])] + "/" + match[2]
            event = state.setdefault("xids", {}).setdefault(key, {"count": 0, "timestamp": 0})
            stamp = stamp_usec / 1e6
            event["count"] += 1
            event["timestamp"] = max(event["timestamp"], stamp)
        state["cursor"] = entry["__CURSOR"]
        state["last_journal_usec"] = max(state.get("last_journal_usec", 0), stamp_usec)


def journal(state, devices, metrics):
    scan_start = time.time()
    args = ["journalctl", "-k", "-b", "-o", "json", "--no-pager"]
    if state.get("cursor"):
        args += ["--after-cursor", state["cursor"]]
    else:
        args += ["--since", "-5min"]
    # A vacuumed cursor must not freeze collection. A timestamp fallback avoids replaying events.
    try:
        output = command(args)
    except subprocess.CalledProcessError:
        output = command(["journalctl", "-k", "-b", "-o", "json", "--no-pager",
                          "--since", "@" + str(state.get("last_journal_usec", 0) / 1e6
                                               or state.get("journal_timestamp", scan_start - 300))])
    parse_journal(output, state, devices)
    state["journal_timestamp"] = scan_start
    for key, event in state.get("xids", {}).items():
        uuid, code = key.split("/")
        labels = {"uuid": uuid, "code": code}
        metrics.add("nvidia_gpu_xid_errors_total", event["count"], labels, kind="counter")
        metrics.add("nvidia_gpu_xid_last_timestamp_seconds", event["timestamp"], labels)


def atomic_write(path, data):
    path = Path(path)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(data)
    os.replace(temporary, path)


def collect(settings, state):
    metrics = Metrics()
    started = time.time()
    devices = {}

    def run(name, action):
        try:
            action()
            metrics.add("nvidia_gpu_collector_success", 1, {"collector": name})
        except Exception as error:
            print(f"{name}: {type(error).__name__}: {error}", file=sys.stderr)
            metrics.add("nvidia_gpu_collector_success", 0, {"collector": name})

    def xml():
        snapshot = command(["nvidia-smi", "-q", "-x"], timeout=8)
        # Commit only a complete snapshot; failed collection drops old GPU readings.
        snapshot_metrics = Metrics()
        found = parse_xml(snapshot, settings, snapshot_metrics)
        parse_processes(snapshot, found, snapshot_metrics)
        devices.update(found)
        metrics.lines.extend(snapshot_metrics.lines)
        metrics.types.update(snapshot_metrics.types)

    run("xml", xml)
    run("pmon", lambda: parse_pmon(command(["nvidia-smi", "pmon", "-s", "um", "-c", "1"]), devices, metrics))
    run("nvml", lambda: nvml_metrics(devices, metrics))
    run("journal", lambda: journal(state, devices, metrics))
    metrics.add("nvidia_gpu_collection_timestamp_seconds", time.time())
    metrics.add("nvidia_gpu_collection_duration_seconds", time.time() - started)
    return metrics.render()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--settings", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--state", required=True)
    args = parser.parse_args()
    settings = json.loads(Path(args.settings).read_text())
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    try:
        state = json.loads(Path(args.state).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        state = {}
    if state.get("boot") != boot:
        state = {"boot": boot}
    output = collect(settings, state)
    atomic_write(args.state, json.dumps(state))
    atomic_write(args.output, output)


if __name__ == "__main__":
    main()
