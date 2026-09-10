#!/usr/bin/env python3
"""Collector regression checks and generated promtool alert tests (no real notifications)."""

import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gpu_metrics", ROOT / "nixos/modules/telemetry/gpu-metrics.py")
gpu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gpu)
SETTINGS = {"uuids": ["GPU-aaa"], "temperatureWarning": 83,
            "temperatureCritical": 88, "memoryFreeWarningMiB": 128}
XML = """<nvidia_smi_log><driver_version>595.71.05</driver_version><cuda_version>13.2</cuda_version>
<gpu id="00000000:01:00.0"><uuid>GPU-aaa</uuid><product_name>Test GPU</product_name>
<temperature><gpu_temp>77 C</gpu_temp><memory_temp>N/A</memory_temp><gpu_temp_tlimit>-2 C</gpu_temp_tlimit></temperature>
<fb_memory_usage><free>287 MiB</free></fb_memory_usage><pci><tx_util>100 KB/s</tx_util></pci>
<clocks_event_reasons><thermal>Not Active</thermal></clocks_event_reasons>
<processes><process_info><pid>42</pid><process_name>/bin/serve</process_name><type>C</type><used_memory>200 MiB</used_memory></process_info></processes>
</gpu><gpu id="00000000:02:00.0"><uuid>GPU-bbb</uuid><product_name>Second GPU</product_name></gpu></nvidia_smi_log>"""


class CollectorTests(unittest.TestCase):
    def test_units_and_unavailable(self):
        self.assertEqual(gpu.number("287 MiB"), (287 * 2**20, "bytes"))
        self.assertEqual(gpu.number("100 KB/s"), (102400, "bytes_per_second"))
        self.assertEqual(gpu.number("25 %"), (0.25, "ratio"))
        self.assertEqual(gpu.number("-2 C"), (-2, "celsius"))
        self.assertEqual(gpu.number("16x"), (16, "lanes"))
        self.assertAlmostEqual(gpu.number("100 us")[0], 0.0001)
        for text in ("N/A", "[N/A]", "595.71.05", "98.02.69.00.72", "0x1234"):
            self.assertIsNone(gpu.number(text))

    def test_uuid_selection_and_unsupported_fields(self):
        metrics = gpu.Metrics()
        devices = gpu.parse_xml(XML, SETTINGS, metrics)
        self.assertEqual(list(devices), [0])
        data = metrics.render()
        self.assertNotIn('uuid="bbb"', data)
        self.assertIn('nvidia_gpu_field_available{field="temperature/memory_temp",uuid="aaa"} 0', data)
        self.assertNotIn('nvidia_gpu_detail_value{field="temperature/memory_temp"', data)
        identities = [line.rsplit(" ", 1)[0] for line in data.splitlines() if not line.startswith("#")]
        self.assertEqual(len(identities), len(set(identities)))
        all_devices = gpu.parse_xml(XML, SETTINGS | {"uuids": []}, gpu.Metrics())
        self.assertEqual(len(all_devices), 2)

    def test_processes_and_pmon(self):
        metrics = gpu.Metrics()
        devices = gpu.parse_xml(XML, SETTINGS, metrics)
        gpu.parse_processes(XML, devices, metrics)
        gpu.parse_pmon("# gpu pid type sm mem enc dec jpg ofa fb ccpm command\n"
                       "0 42 C 99 15 - - - - 200 0 serve\n", devices, metrics)
        self.assertIn('engine="sm",pid="42",process="serve",type="C",uuid="aaa"} 0.99', metrics.render())
        self.assertNotIn('engine="enc"', metrics.render())
        self.assertIn("nvidia_gpu_process_memory_bytes", metrics.render())
        no_processes = gpu.Metrics()
        gpu.parse_processes(XML.replace("<process_info>", "<gone>").replace("</process_info>", "</gone>"), devices, no_processes)
        self.assertNotIn("nvidia_gpu_process_memory_bytes", no_processes.render())

    def test_xid_bus_normalization_dedup_and_new_event(self):
        state = {}
        devices = {0: {"uuid": "aaa", "pci_bus_id": "00000000:01:00.0"}}
        entry = {"MESSAGE": "NVRM: Xid (PCI:0000:01:00): 79, GPU has fallen off the bus.",
                 "__REALTIME_TIMESTAMP": "1000000", "__CURSOR": "first"}
        gpu.parse_journal(json.dumps(entry), state, devices)
        self.assertEqual(state["xids"]["aaa/79"]["count"], 1)
        gpu.parse_journal(json.dumps(entry), state, devices)
        self.assertEqual(state["xids"]["aaa/79"]["count"], 1)
        entry.update(__REALTIME_TIMESTAMP="2000000", __CURSOR="second")
        gpu.parse_journal(json.dumps(entry), state, {})
        self.assertEqual(state["xids"]["aaa/79"], {"count": 2, "timestamp": 2})

    def test_collection_failure_drops_readings_and_exposes_failure(self):
        with patch.object(gpu, "command", side_effect=RuntimeError("driver unavailable")), \
             patch.object(gpu, "nvml_metrics", return_value=None):
            result = gpu.collect(SETTINGS, {})
        self.assertIn('nvidia_gpu_collector_success{collector="xml"} 0', result)
        self.assertIn("nvidia_gpu_collection_timestamp_seconds", result)
        self.assertNotIn("nvidia_gpu_detail_value", result)

    def test_atomic_file_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gpu.prom"
            gpu.atomic_write(path, "old\n")
            gpu.atomic_write(path, "new\n")
            self.assertEqual(path.read_text(), "new\n")
            self.assertFalse(path.with_suffix(".tmp").exists())


def write_alert_tests(rules_path, output):
    rules = json.loads(Path(rules_path).read_text())
    definitions = {r["alert"]: r for r in rules["groups"][0]["rules"] if "alert" in r}
    uuid = "d8ec4dea-3771-68e6-9f8b-11811e47ac9d"
    base = {"instance": "b650", "uuid": uuid}

    def series(name, value, labels=None):
        tags = ",".join(f'{k}="{v}"' for k, v in (base if labels is None else labels).items())
        return {"series": f"{name}{{{tags}}}", "values": value}

    def case(name, samples, time, expected=None):
        definition = definitions[name]
        alerts = []
        if expected is not None:
            labels, value = expected
            annotations = {k: v.replace("{{ $labels.instance }}", "b650")
                            .replace("{{ $labels.uuid }}", labels.get("uuid", ""))
                            .replace("{{ $labels.code }}", labels.get("code", ""))
                            .replace("{{ $labels.collector }}", labels.get("collector", ""))
                            .replace("{{ $value }}", str(value))
                           for k, v in definition["annotations"].items()}
            alerts = [{"exp_labels": labels | definition["labels"], "exp_annotations": annotations}]
        return {"interval": "15s", "input_series": samples,
                "alert_rule_test": [{"eval_time": time, "alertname": name, "exp_alerts": alerts}]}

    tests = [
        case("GPUTemperatureCritical", [series("nvidia_smi_temperature_gpu", "90+0x20"),
                                      series("nvidia_gpu_temperature_critical_celsius", "88+0x20")],
             "3m", (base, 90)),
        case("GPUTemperatureCritical", [series("nvidia_smi_temperature_gpu", "90+0x3 70+0x20"),
                                      series("nvidia_gpu_temperature_critical_celsius", "88+0x24")], "3m"),
        case("GPUMemoryHeadroomLow", [series("nvidia_smi_memory_free_bytes", f"{287 * 2**20}+0x80"),
                                     series("nvidia_gpu_memory_free_warning_bytes", f"{128 * 2**20}+0x80")], "20m"),
        case("GPUThermalThrottling", [series("nvidia_smi_clocks_event_reasons_sw_power_cap", "1+0x40"),
                                     series("nvidia_smi_clocks_event_reasons_hw_thermal_slowdown", "0+0x40")], "10m"),
        case("GPUDeviceMissing", [series("up", "1+0x40", {"instance": "b650", "job": "nvidia-gpu"})],
             "6m", (base, 1)),
        case("GPUDeviceMissing", [series("up", "1+0x40", {"instance": "b650", "job": "nvidia-gpu"}),
                                  series("nvidia_smi_gpu_info", "1+0x40")], "6m"),
        case("GPUDetailCollectionStale", [series("nvidia_gpu_collection_timestamp_seconds", "0+0x30", {"instance": "b650"})],
             "5m", ({"instance": "b650"}, 300)),
        case("GPUUncorrectableECC", [], "5m"),
        case("GPUXidError", [series("nvidia_gpu_xid_last_timestamp_seconds", "0+0x60", base | {"code": "63"})], "5m"),
        case("GPUXidCritical", [series("nvidia_gpu_xid_last_timestamp_seconds", "10+0x40", base | {"code": "79"})],
             "1m", (base | {"code": "79"}, 50)),
        case("GPUXidCritical", [series("nvidia_gpu_xid_last_timestamp_seconds", "0+0x80", base | {"code": "79"})], "20m"),
        case("GPUDetailCollectorFailed", [series("nvidia_gpu_collector_success", "0+0x40",
                                                {"instance": "b650", "collector": "xml"})],
             "6m", ({"instance": "b650", "collector": "xml"}, 0)),
    ]
    Path(output).write_text(json.dumps({"rule_files": [str(Path(rules_path).absolute())],
                                       "evaluation_interval": "15s", "tests": tests}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules")
    parser.add_argument("--promtool-tests")
    parser.add_argument("--prometheus-url")
    args = parser.parse_args()
    if (args.prometheus_url or args.promtool_tests) and not args.rules:
        parser.error("--rules is required for Prometheus validation")
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CollectorTests))
    if not result.wasSuccessful():
        raise SystemExit(1)
    if args.rules and args.promtool_tests:
        write_alert_tests(args.rules, args.promtool_tests)
    if args.prometheus_url:
        expected = {r["alert"] for g in json.loads(Path(args.rules).read_text())["groups"]
                    for r in g["rules"] if "alert" in r}
        with urllib.request.urlopen(args.prometheus_url.rstrip("/") + "/api/v1/rules", timeout=15) as response:
            data = json.load(response)
        loaded = {r["name"]: r for g in data["data"]["groups"] for r in g["rules"]}
        assert expected <= loaded.keys(), f"GPU rules not loaded: {expected - loaded.keys()}"
        assert all(loaded[name]["health"] == "ok" and not loaded[name].get("lastError")
                   for name in expected), "GPU rule evaluation is unhealthy"
        print(f"LIVE: {len(expected)} GPU alerts loaded and healthy at {args.prometheus_url}")
