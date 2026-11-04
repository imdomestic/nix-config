"""Evaluate the deployed Gaoji rule document with synthetic, offline metrics."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--promtool", type=Path, required=True)
    args = parser.parse_args()
    rules = json.loads(args.rules.read_text())["groups"][0]["rules"]
    names = {rule["alert"]: rule for rule in rules}
    unavailable = "GaojiOfficialUnavailable"
    gap = "GaojiOfficialMessageGap"
    missing = "GaojiOfficialMetricsUnavailable"
    assert set(names) == {unavailable, gap, missing}
    cases = [
        ("ready", "1+0x10", "1+0x10", "0+0x10", set()),
        ("lease lost", "1+0x10", "0+0x10", "0+0x10", {unavailable}),
        ("historical gap with ready transport", "1+0x10", "1+0x10", "1+0x10", {gap}),
        ("metrics scrape failed", "0+0x10", None, None, {missing}),
        ("brief interruption recovered", "1+0x10", "0+0x1 1+0x8", "0+0x10", set()),
    ]
    tests = []
    for title, up, healthy, message_gap, expected in cases:
        metrics = {"up": up, "gaoji_qq_official_healthy": healthy,
                   "gaoji_qq_official_message_gap": message_gap}
        checks = []
        for name, rule in names.items():
            checks.append({"eval_time": "3m", "alertname": name, "exp_alerts": [
                {"exp_labels": {"instance": "tank", "job": "gaoji", **rule["labels"]},
                 "exp_annotations": rule["annotations"]}
            ] if name in expected else []})
        tests.append({"name": title, "interval": "1m", "input_series": [
            {"series": metric + '{job="gaoji",instance="tank"}', "values": values}
            for metric, values in metrics.items() if values is not None
        ], "alert_rule_test": checks})
    with tempfile.TemporaryDirectory(prefix="gaoji-alerts-") as directory:
        test_file = Path(directory) / "tests.json"
        test_file.write_text(json.dumps({"rule_files": [str(args.rules.resolve())],
                                         "evaluation_interval": "1m", "tests": tests}))
        subprocess.run([str(args.promtool), "check", "rules", str(args.rules)],
                       check=True, timeout=30)
        subprocess.run([str(args.promtool), "test", "rules", str(test_file)],
                       cwd=directory, check=True, timeout=30)
    print("PASS: ready, lease loss, historical gap, missing scrape, transient recovery")


if __name__ == "__main__":
    main()
