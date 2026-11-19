"""Offline regression coverage for retiring Pi's CLIProxy Gemini selections."""

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

source = Path(__file__).with_name("migrate-pi-agy.py")
spec = importlib.util.spec_from_file_location("migration", source)
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)
models = [
    {"id": "gemini-4-hydrogen-high", "levels": ["high"]},
    {"id": "gemini-3-flash", "levels": ["minimal", "low", "medium", "high"]},
]


class MigrationTests(unittest.TestCase):
    def test_only_retired_defaults_move_and_fixed_effort_is_clamped(self):
        before = {"defaultProvider": "cliproxy", "defaultModel": "gemini-4-hydrogen-high", "defaultThinkingLevel": "xhigh", "theme": "unchanged"}
        original = copy.deepcopy(before)
        after = migration.migrate(before, models)
        self.assertEqual(after, {**before, "defaultProvider": "agy", "defaultThinkingLevel": "high"})
        self.assertEqual(before, original)
        self.assertEqual(migration.migrate(after, models), after)

    def test_custom_defaults_and_other_providers_are_untouched(self):
        for provider, model in [("agy", "gemini-4-hydrogen-high"), ("google", "gemini-4-hydrogen-high"), ("cliproxy", "gpt-6.1-sol"), ("cliproxy", "other/gemini-4-argon"), ("cliproxy", "gemini-unlisted")]:
            before = {"defaultProvider": provider, "defaultModel": model, "defaultThinkingLevel": "xhigh"}
            self.assertEqual(migration.migrate(before, models), before)
        self.assertEqual(migration.migrate({}, models), {})

    def test_nonfixed_model_preserves_effort(self):
        before = {"defaultProvider": "cliproxy", "defaultModel": "gemini-3-flash", "defaultThinkingLevel": "medium"}
        self.assertEqual(migration.migrate(before, models), {**before, "defaultProvider": "agy"})

    def test_scoped_gemini_patterns_move_without_touching_other_scopes(self):
        before = {"enabledModels": ["cliproxy/gemini-*", "cliproxy/gemini-4-hydrogen-high:high", "cliproxy/*", "google/*", "gemini-3-flash"]}
        self.assertEqual(migration.migrate(before, models)["enabledModels"], ["agy/gemini-*", "agy/gemini-4-hydrogen-high:high", "cliproxy/*", "google/*", "gemini-3-flash"])

    def test_hydrogen_only_migration_leaves_other_gemini_unchanged(self):
        hydrogen = [m for m in models if m["id"].startswith("gemini-4-hydrogen-")]
        before = {"defaultProvider": "cliproxy", "defaultModel": "gemini-4-hydrogen-high", "defaultThinkingLevel": "xhigh", "enabledModels": ["cliproxy/gemini-4-hydrogen-*:high", "cliproxy/gemini-3-flash", "cliproxy/gemini-*", "cliproxy/*"]}
        after = migration.migrate(before, hydrogen, "gemini-4-hydrogen-")
        self.assertEqual(after["defaultProvider"], "agy")
        self.assertEqual(after["defaultThinkingLevel"], "high")
        self.assertEqual(after["enabledModels"], ["agy/gemini-4-hydrogen-*:high", "cliproxy/gemini-3-flash", "cliproxy/gemini-*", "cliproxy/*"])
        self.assertEqual(migration.migrate(after, hydrogen, "gemini-4-hydrogen-"), after)
        flash = {"defaultProvider": "cliproxy", "defaultModel": "gemini-3-flash"}
        self.assertEqual(migration.migrate(flash, hydrogen, "gemini-4-hydrogen-"), flash)
        xhigh = [{"id": "gemini-4-hydrogen-xhigh", "levels": ["xhigh"]}]
        before = {"defaultProvider": "cliproxy", "defaultModel": xhigh[0]["id"], "defaultThinkingLevel": "high"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text(json.dumps(before))
            subprocess.run([sys.executable, str(source), str(path), json.dumps(xhigh), "gemini-4-hydrogen-"], check=True)
            self.assertEqual(json.loads(path.read_text()), {**before, "defaultProvider": "agy", "defaultThinkingLevel": "xhigh"})

    def test_atomic_cli_is_private_idempotent_and_missing_file_is_not_created(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            command = [sys.executable, str(source), str(path), json.dumps(models)]
            subprocess.run(command, check=True)
            self.assertFalse(path.exists())
            path.write_text(json.dumps({"defaultProvider": "cliproxy", "defaultModel": "gemini-4-hydrogen-high", "custom": {"keep": True}}))
            original_inode = path.stat().st_ino
            subprocess.run(command, check=True)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(path.stat().st_ino, original_inode)
            self.assertTrue(json.loads(path.read_text())["custom"]["keep"])
            before = path.stat()
            subprocess.run(command, check=True)
            self.assertEqual(path.stat().st_ino, before.st_ino)
            self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertEqual(os.listdir(directory), ["settings.json"])


if __name__ == "__main__":
    unittest.main()
