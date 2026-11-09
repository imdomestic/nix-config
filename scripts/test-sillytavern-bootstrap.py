#!/usr/bin/env python3
"""Focused stdlib tests against an isolated mock of the pinned 1.18 REST API.

python3 scripts/test-sillytavern-bootstrap.py [--source /path/to/SillyTavern]

The upstream settings and shipped preset are read as test oracles, not vendored.
The only HTTP listener used by these tests is ephemeral and bound to loopback.
No production APIs, model catalogs or inference endpoints are contacted.
"""

import argparse
import base64
import contextlib
import copy
import importlib.util
import io
import json
import sys
import tempfile
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path("/nix/store/gbddqcspj3v5wgw2v7p6w47q5cgzf8fx-source")
SPEC = importlib.util.spec_from_file_location("sillytavern_bootstrap", ROOT / "system/modules/sillytavern/bootstrap.py")
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class MockTavern:
    """Models /settings, /presets and 1.18's array-of-secrets + active rotation."""

    def __init__(self):
        self.settings = json.loads((SOURCE / "default/content/settings.json").read_text())
        self.default = json.loads((SOURCE / "default/content/presets/openai/Default.json").read_text())
        self.presets = {"Default": copy.deepcopy(self.default)}
        self.secrets = []
        self.calls = []
        self.failures = []
        self.auth = "Basic " + base64.b64encode("linwhite:password:with spaces ".encode()).decode()
        self.csrf = "test-csrf-token"
        self.version = "1.18.0"
        self.accounts = False
        self.startup_failures = 0
        self.fail_path = None
        self.fail_status = 500
        self.commit_then_fail = False
        self.redirect_path = None
        self.concurrent_edit = False
        self.nested_restore = False
        self.malformed_catalog = False
        self.get_count = 0
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def send(self, status, value=None, headers=None, raw=False):
                self.send_response(status)
                for name, value_header in (headers or {}).items():
                    self.send_header(name, value_header)
                if status != 204:
                    self.send_header("Content-Type", "application/json")
                self.end_headers()
                if value is not None:
                    self.wfile.write(value.encode() if raw else json.dumps(value).encode())

            def error(self, status):
                # Deliberately hostile error body; it must never reach stderr.
                self.send(status, "password:with spaces sk-bonsai-private " + state.auth, raw=True)

            def do_GET(self):
                self.handle_api()

            def do_POST(self):
                self.handle_api()

            def handle_api(self):
                body = None
                if self.command == "POST":
                    length = int(self.headers.get("Content-Length", 0))
                    body = json.loads(self.rfile.read(length))
                state.calls.append((self.command, self.path, copy.deepcopy(body)))
                if self.headers.get("Authorization") != state.auth:
                    self.error(401)
                    return
                if self.path == state.redirect_path:
                    self.send(302, headers={"Location": state.endpoint + "/do-not-follow"})
                    return
                if self.path == "/csrf-token":
                    if state.startup_failures:
                        state.startup_failures -= 1
                        self.error(503)
                        return
                    self.send(200, {"token": state.csrf}, {"Set-Cookie": "session-test=cookie; Path=/; HttpOnly"})
                    return
                if (self.headers.get("Cookie") != "session-test=cookie" or
                        self.headers.get("X-CSRF-Token") != state.csrf):
                    state.failures.append("missing session cookie or CSRF token")
                    self.error(403)
                    return
                if self.command == "POST" and self.headers.get("Content-Type") != "application/json":
                    state.failures.append("missing JSON Content-Type")
                    self.error(400)
                    return
                if self.path == state.fail_path and not state.commit_then_fail:
                    self.error(state.fail_status)
                    return
                if self.path == "/version" and self.command == "GET":
                    self.send(200, {"pkgVersion": state.version, "gitRevision": "not-a-production-server"})
                elif self.path == "/api/settings/get" and self.command == "POST":
                    state.get_count += 1
                    if state.concurrent_edit and state.get_count == 2:
                        state.settings["power_user"]["theme"] = "concurrent-user-choice"
                    names = sorted(state.presets)
                    self.send(200, {
                        "settings": json.dumps(state.settings),
                        "openai_setting_names": names,
                        "openai_settings": [json.dumps(state.presets[name]) for name in names] if not state.malformed_catalog else [],
                        "enable_accounts": state.accounts, "enable_extensions": True,
                        "world_names": ["do-not-touch"], "koboldai_settings": [],
                    })
                elif self.path == "/api/settings/save" and self.command == "POST":
                    state.settings = copy.deepcopy(body)
                    self.send(200, {"result": "ok"})
                elif self.path == "/api/presets/restore" and self.command == "POST":
                    if body != {"apiId": "openai", "name": "Default"}:
                        state.failures.append("invalid preset restore schema")
                    value = json.dumps(state.default) if state.nested_restore else state.default
                    self.send(200, {"isDefault": True, "preset": value})
                elif self.path == "/api/presets/save" and self.command == "POST":
                    if set(body) != {"apiId", "name", "preset"} or body["apiId"] != "openai" or not isinstance(body["preset"], dict):
                        state.failures.append("invalid preset save schema")
                    state.presets[body["name"]] = copy.deepcopy(body["preset"])
                    self.send(200, {"name": body["name"]})
                elif self.path == "/api/secrets/read" and self.command == "POST":
                    # /read exposes IDs, labels, active flags, and *masked* values.
                    self.send(200, {
                        "api_key_custom": [{**secret, "value": "*******xyz"} for secret in state.secrets] or None,
                        "api_key_openai": None,
                    })
                elif self.path == "/api/secrets/write" and self.command == "POST":
                    if set(body) != {"key", "value", "label"} or body["key"] != "api_key_custom" or not isinstance(body["value"], str):
                        state.failures.append("invalid secret write schema")
                    secret_id = state.add_secret(body["value"], body["label"])
                    if self.path == state.fail_path and state.commit_then_fail:
                        state.fail_path = None
                        self.error(state.fail_status)
                    else:
                        self.send(200, {"id": secret_id})
                elif self.path == "/api/secrets/rotate" and self.command == "POST":
                    if set(body) != {"key", "id"} or body["key"] != "api_key_custom":
                        state.failures.append("invalid secret rotate schema")
                    if not any(secret["id"] == body["id"] for secret in state.secrets):
                        state.failures.append("rotating an absent secret")
                    state.rotate(body["id"])
                    self.send(204)
                else:
                    state.failures.append("unexpected API route or method")
                    self.error(404)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def add_secret(self, value, label):
        secret_id = str(uuid.uuid4())
        self.rotate(secret_id)
        self.secrets.append({"id": secret_id, "value": value, "label": label, "active": True})
        return secret_id

    def rotate(self, secret_id):
        for secret in self.secrets:
            secret["active"] = secret["id"] == secret_id

    def active(self):
        return next((secret for secret in self.secrets if secret["active"]), None)

    def profiles(self):
        return {profile["id"]: profile for profile in self.settings["extension_settings"]["connectionManager"]["profiles"]}

    def writes(self):
        return [path for method, path, _body in self.calls if method == "POST" and path.endswith(("/save", "/write", "/rotate"))]


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tavern = MockTavern()
        self.addCleanup(self.tavern.close)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        directory = Path(self.tmp.name)
        self.password_file = directory / "password"
        self.password_file.write_text("password:with spaces \n")
        self.bonsai_file = directory / "bonsai"
        self.bonsai_file.write_text("sk-bonsai-private\n")
        self.cliproxy_file = directory / "cliproxy"
        self.cliproxy_file.write_text("sk-cliproxy-private\n")
        self.manifest = {
            "endpoint": self.tavern.endpoint, "username": "linwhite",
            "passwordFile": str(self.password_file),
            "credentials": {"cliproxy": str(self.cliproxy_file), "bonsai": str(self.bonsai_file)},
            "defaultProfile": "fleet-bonsai-hikari",
            "profiles": [
                {"id": "fleet-bonsai-hikari", "name": "Bonsai Hikari · seraph",
                 "url": "http://offline.invalid:8080/v1", "model": "bonsai-hikari",
                 "credential": "bonsai", "context": 174080, "maxTokens": 2048,
                 "reasoningEffort": "medium"},
                {"id": "fleet-cliproxy", "name": "CLIProxy · all models",
                 "url": "http://other-offline.invalid:8317/v1", "model": "initial-model",
                 "credential": "cliproxy", "context": 131072, "maxTokens": 4096},
                {"id": "fleet-qwen-swift", "name": "Qwen3.8 Swift · taipan",
                 "url": "http://third-offline.invalid:8000/v1", "model": "qwen3.8-27b",
                 "context": 262144, "maxTokens": 4096},
                {"id": "fleet-ollama", "name": "Ollama · seraph",
                 "url": "http://fourth-offline.invalid:11434/v1/", "model": "local-model",
                 "credential": None, "context": 32768, "maxTokens": 2048},
            ],
        }
        self.manifest_path = directory / "manifest.json"

    def run_helper(self, expected=0):
        self.manifest_path.write_text(json.dumps(self.manifest))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = bootstrap.main([str(self.manifest_path)])
        self.assertEqual(result, expected, err.getvalue())
        self.assertEqual(self.tavern.failures, [])
        for secret in ("password:with spaces", "sk-bonsai-private", "sk-cliproxy-private", self.tavern.auth):
            self.assertNotIn(secret, out.getvalue() + err.getvalue())
        return out.getvalue(), err.getvalue()

    def test_first_provisioning_exact_upstream_fields_and_independent_secrets(self):
        original = copy.deepcopy(self.tavern.settings)
        self.run_helper()
        profiles = self.tavern.profiles()
        hikari = profiles["fleet-bonsai-hikari"]
        self.assertEqual({key: hikari[key] for key in ("mode", "api", "api-url", "model", "preset", "proxy", "prompt-post-processing", "exclude")}, {
            "mode": "cc", "api": "custom", "api-url": "http://offline.invalid:8080/v1",
            "model": "bonsai-hikari", "preset": "Fleet - fleet-bonsai-hikari",
            "proxy": "None", "prompt-post-processing": "none", "exclude": [],
        })
        self.assertEqual(self.tavern.settings["extension_settings"]["connectionManager"]["selectedProfile"], hikari["id"])
        self.assertEqual(self.tavern.settings["main_api"], "openai")
        oai = self.tavern.settings["oai_settings"]
        self.assertEqual(oai["custom_model"], "bonsai-hikari")
        self.assertEqual(oai["openai_max_context"], 174080)
        self.assertEqual(oai["temp_openai"], 0.8)
        self.assertNotIn("temperature", oai)  # upstream settings/preset alias distinction
        self.assertEqual(oai["prompts"], original["oai_settings"]["prompts"])
        self.assertEqual(self.tavern.settings["power_user"], original["power_user"])
        self.assertEqual(self.tavern.settings["tag_map"], original["tag_map"])
        self.assertTrue(self.tavern.settings["firstRun"])  # onboarding remains user's state
        self.assertEqual(self.tavern.active()["id"], hikari["secret-id"])
        by_id = {secret["id"]: secret for secret in self.tavern.secrets}
        self.assertEqual(by_id[hikari["secret-id"]]["value"], "sk-bonsai-private")
        self.assertEqual(by_id[profiles["fleet-cliproxy"]["secret-id"]]["value"], "sk-cliproxy-private")
        self.assertEqual(by_id[profiles["fleet-qwen-swift"]["secret-id"]]["value"], "not-required")
        self.assertEqual(by_id[profiles["fleet-ollama"]["secret-id"]]["value"], "not-required")
        self.assertEqual(len({profile["secret-id"] for profile in profiles.values()}), 4)
        self.assertEqual(profiles["fleet-ollama"]["api-url"], "http://fourth-offline.invalid:11434/v1")
        preset = self.tavern.presets[hikari["preset"]]
        self.assertEqual(preset["prompts"], self.tavern.default["prompts"])
        self.assertEqual(preset["prompt_order"], self.tavern.default["prompt_order"])
        self.assertTrue(preset["max_context_unlocked"])
        self.assertEqual(preset["reasoning_effort"], "medium")
        self.assertEqual(json.loads(preset["custom_include_body"]), {"reasoning_effort": "medium"})
        for profile in profiles.values():
            preset = self.tavern.presets[profile["preset"]]
            self.assertEqual(preset["custom_url"], profile["api-url"])
            self.assertEqual(preset["custom_model"], profile["model"])
            if profile["id"] in ("fleet-qwen-swift", "fleet-ollama"):
                self.assertEqual(json.loads(preset["custom_include_headers"]), {"Authorization": "Bearer not-required"})
            else:
                self.assertEqual(preset["custom_include_headers"], "")
            self.assertEqual(preset["reverse_proxy"], "")
        self.assertTrue(all(path in bootstrap.API_PATHS for _, path, _ in self.tavern.calls))
        self.assertNotIn("/api/presets/restore", [path for _, path, _ in self.tavern.calls])

    def test_keyless_authorization_is_safe_before_and_after_native_secret_rotation(self):
        self.run_helper()
        profiles = self.tavern.profiles()
        keyed = ("fleet-bonsai-hikari", "fleet-cliproxy")
        keyless = ("fleet-qwen-swift", "fleet-ollama")
        by_id = {secret["id"]: secret for secret in self.tavern.secrets}
        for previous in keyed:
            for target in keyless:
                with self.subTest(previous=previous, target=target):
                    self.tavern.rotate(profiles[previous]["secret-id"])
                    preset = self.tavern.presets[profiles[target]["preset"]]
                    # Exact native /status and /generate merge order: the
                    # active secret is read before {...Authorization, ...headers}.
                    # CM applies preset/api-url first and secret-id last.
                    headers = {"Authorization": "Bearer " + self.tavern.active()["value"],
                               **json.loads(preset["custom_include_headers"])}
                    self.assertEqual(headers["Authorization"], "Bearer not-required")
                    self.tavern.rotate(profiles[target]["secret-id"])
                    value = by_id[profiles[target]["secret-id"]]["value"]
                    self.assertEqual(value, "not-required")
                    headers = {"Authorization": "Bearer " + value,
                               **json.loads(preset["custom_include_headers"])}
                    self.assertEqual(headers["Authorization"], "Bearer not-required")

    def test_second_run_is_a_true_noop(self):
        self.run_helper()
        before = copy.deepcopy((self.tavern.settings, self.tavern.presets, self.tavern.secrets))
        self.tavern.calls.clear()
        self.run_helper()
        self.assertEqual((self.tavern.settings, self.tavern.presets, self.tavern.secrets), before)
        self.assertEqual(self.tavern.writes(), [])

    def test_user_settings_profile_edits_presets_and_selection_survive(self):
        self.run_helper()
        profiles = self.tavern.profiles()
        profiles["fleet-bonsai-hikari"].update({"name": "My renamed profile", "model": "user-model", "preset": "My roleplay", "exclude": ["proxy"], "user-extra": 42})
        self.tavern.presets["My roleplay"] = {**copy.deepcopy(self.tavern.default), "temperature": 1.7}
        self.tavern.presets[profiles["fleet-cliproxy"]["preset"]]["temperature"] = 1.4
        self.tavern.settings["firstRun"] = False
        self.tavern.settings["power_user"]["theme"] = "user-customized"
        self.tavern.settings["extension_settings"]["someOtherExtension"] = {"keep": [1, 2, 3]}
        manager = self.tavern.settings["extension_settings"]["connectionManager"]
        manager["selectedProfile"] = "fleet-qwen-swift"
        self.tavern.settings["oai_settings"].update({"custom_url": profiles["fleet-qwen-swift"]["api-url"], "custom_model": "user-qwen-model", "temp_openai": 1.3})
        self.tavern.rotate(profiles["fleet-qwen-swift"]["secret-id"])
        self.manifest["defaultProfile"] = "fleet-cliproxy"
        self.manifest["profiles"][0]["model"] = "manifest-new-model"
        self.manifest["profiles"][1]["maxTokens"] = 8192
        before = copy.deepcopy((self.tavern.settings, self.tavern.presets, self.tavern.secrets))
        self.tavern.calls.clear()
        self.run_helper()
        self.assertEqual((self.tavern.settings, self.tavern.presets, self.tavern.secrets), before)
        self.assertEqual(self.tavern.writes(), [])

    def test_secret_rotation_repairs_managed_ids_without_selecting_new_default(self):
        self.run_helper()
        before_profiles = copy.deepcopy(self.tavern.profiles())
        before_presets = copy.deepcopy(self.tavern.presets)
        profiles = self.tavern.profiles()
        profiles["fleet-bonsai-hikari"]["name"] = "My Hikari"
        profiles["fleet-bonsai-hikari"]["model"] = "user-preferred-model"
        self.bonsai_file.write_text("sk-bonsai-rotated\n")
        self.manifest["defaultProfile"] = "fleet-cliproxy"
        self.run_helper()
        after = self.tavern.profiles()
        self.assertNotEqual(after["fleet-bonsai-hikari"]["secret-id"], before_profiles["fleet-bonsai-hikari"]["secret-id"])
        self.assertEqual(after["fleet-bonsai-hikari"]["name"], "My Hikari")
        self.assertEqual(after["fleet-bonsai-hikari"]["model"], "user-preferred-model")
        self.assertEqual(after["fleet-cliproxy"], before_profiles["fleet-cliproxy"])
        self.assertEqual(self.tavern.active()["value"], "sk-bonsai-rotated")
        self.assertEqual(self.tavern.settings["extension_settings"]["connectionManager"]["selectedProfile"], "fleet-bonsai-hikari")
        self.assertTrue(any(secret["id"] == before_profiles["fleet-bonsai-hikari"]["secret-id"] for secret in self.tavern.secrets))
        self.assertEqual(self.tavern.presets, before_presets)
        self.tavern.calls.clear()
        self.run_helper()
        self.assertEqual(self.tavern.writes(), [])

    def test_user_endpoint_is_not_rebound_to_rotated_credentials(self):
        self.run_helper()
        hikari = self.tavern.profiles()["fleet-bonsai-hikari"]
        hikari["api-url"] = "http://user-provider.invalid/v1"
        before = copy.deepcopy(hikari)
        old_active = self.tavern.active()["id"]
        self.bonsai_file.write_text("new-runtime-key")
        self.run_helper()
        self.assertEqual(self.tavern.profiles()[hikari["id"]], before)
        self.assertEqual(self.tavern.active()["id"], old_active)

    def test_untouched_connection_updates_atomically_and_named_keys_are_shared(self):
        self.run_helper()
        before = copy.deepcopy(self.tavern.presets)
        spec = self.manifest["profiles"][0]
        spec.update({"url": "http://new-offline.invalid/v1", "model": "new-model", "credential": "cliproxy"})
        second = {**spec, "id": "fleet-second-cliproxy", "name": "Another CLIProxy convenience"}
        self.manifest["profiles"].append(second)
        self.run_helper()
        profiles = self.tavern.profiles()
        hikari = profiles[spec["id"]]
        self.assertEqual(hikari["api-url"], spec["url"])
        self.assertEqual(hikari["model"], "new-model")
        self.assertEqual(hikari["secret-id"], profiles["fleet-cliproxy"]["secret-id"])
        self.assertEqual(hikari["secret-id"], profiles[second["id"]]["secret-id"])
        for name, value in before.items():
            self.assertEqual(self.tavern.presets[name], value)
        self.assertEqual(len([secret for secret in self.tavern.secrets if secret["value"] == "sk-cliproxy-private"]), 1)

    def test_existing_user_is_not_reselected_or_given_a_provider_key(self):
        self.tavern.settings["firstRun"] = False
        self.tavern.settings["main_api"] = "openai"
        self.tavern.settings["oai_settings"].update({"chat_completion_source": "custom", "custom_url": "http://user-keyless.invalid/v1", "custom_model": "user-model"})
        original = copy.deepcopy(self.tavern.settings)
        self.run_helper()
        self.assertIsNone(self.tavern.settings["extension_settings"]["connectionManager"]["selectedProfile"])
        self.assertEqual(self.tavern.settings["oai_settings"], original["oai_settings"])
        self.assertEqual(self.tavern.active()["value"], "not-required")

    def test_original_user_preset_is_cloned_and_missing_seed_is_not_rebased(self):
        base = copy.deepcopy(self.tavern.default)
        base["prompts"][0]["content"] = "Original user's roleplay prompt"
        base["custom_include_headers"] = "Authorization: obsolete-provider-key"
        base["custom_include_body"] = "model: wrong-model"
        self.tavern.presets["My base"] = base
        self.tavern.settings["oai_settings"]["preset_settings_openai"] = "My base"
        self.run_helper()
        hikari = self.tavern.profiles()["fleet-bonsai-hikari"]
        seeded = copy.deepcopy(self.tavern.presets[hikari["preset"]])
        self.assertEqual(seeded["prompts"], base["prompts"])
        self.assertEqual(seeded["custom_include_headers"], "")
        self.assertEqual(json.loads(seeded["custom_include_body"]), {"reasoning_effort": "medium"})
        del self.tavern.presets[hikari["preset"]]
        self.tavern.presets["Later base"] = {**copy.deepcopy(self.tavern.default), "temperature": 1.9}
        self.tavern.settings["oai_settings"]["preset_settings_openai"] = "Later base"
        self.manifest["profiles"][0]["temperature"] = 1.8
        self.run_helper()
        self.assertEqual(self.tavern.presets[hikari["preset"]], seeded)
        self.assertEqual(self.tavern.settings["oai_settings"]["preset_settings_openai"], "Later base")

    def test_shipped_default_fallback_and_exact_nested_catalog_shapes(self):
        self.tavern.presets.clear()
        self.tavern.nested_restore = True
        self.run_helper()
        self.assertIn("/api/presets/restore", [path for _, path, _ in self.tavern.calls])
        self.assertEqual(self.tavern.presets["Fleet - fleet-bonsai-hikari"]["prompts"], self.tavern.default["prompts"])
        self.assertEqual(bootstrap.object_value(json.dumps({"a": 1})), {"a": 1})
        self.assertEqual(bootstrap.catalog_presets({"openai_setting_names": ["Default"], "openai_settings": [json.dumps(self.tavern.default)]})["Default"], self.tavern.default)

    def test_partial_failure_restores_user_secret_and_retry_recovers_labels(self):
        old = self.tavern.add_secret("user-private-key", "User's own secret")
        self.tavern.fail_path = "/api/secrets/write"
        self.tavern.commit_then_fail = True
        self.run_helper(expected=1)
        self.assertEqual(self.tavern.active()["id"], old)
        self.assertNotIn("fleetBootstrap", self.tavern.settings["extension_settings"])
        self.assertEqual(len([secret for secret in self.tavern.secrets if secret["value"] == "sk-cliproxy-private"]), 1)
        self.run_helper()
        self.assertEqual(len([secret for secret in self.tavern.secrets if secret["value"] == "sk-cliproxy-private"]), 1)
        self.assertTrue(any(secret["id"] == old for secret in self.tavern.secrets))

    def test_concurrent_user_edit_is_not_overwritten(self):
        old = self.tavern.add_secret("old-user-key", "User secret")
        self.tavern.concurrent_edit = True
        _out, err = self.run_helper(expected=1)
        self.assertIn("concurrently", err)
        self.assertEqual(self.tavern.settings["power_user"]["theme"], "concurrent-user-choice")
        self.assertNotIn("/api/settings/save", [path for _, path, _ in self.tavern.calls])
        self.assertEqual(self.tavern.active()["id"], old)

    def test_retry_after_interrupted_settings_save_reuses_owned_presets(self):
        self.tavern.concurrent_edit = True
        self.run_helper(expected=1)
        old_presets = copy.deepcopy(self.tavern.presets)
        old_secrets = copy.deepcopy(self.tavern.secrets)
        self.tavern.concurrent_edit = False
        self.tavern.settings["oai_settings"]["preset_settings_openai"] = "Default"
        self.tavern.presets["Default"]["prompts"][0]["content"] = "Later user choice"
        self.tavern.calls.clear()
        self.run_helper()
        for name, preset in old_presets.items():
            if name != "Default":
                self.assertEqual(self.tavern.presets[name], preset)
        self.assertEqual(len(self.tavern.secrets), len(old_secrets))
        self.assertNotIn("/api/presets/save", self.tavern.writes())
        self.assertNotIn("/api/secrets/write", self.tavern.writes())
        self.assertEqual(self.tavern.settings["power_user"]["theme"], "concurrent-user-choice")

    def test_readiness_retries_startup_but_not_authentication_errors(self):
        self.tavern.startup_failures = 2
        self.manifest["readinessTimeoutSeconds"] = 120
        with mock.patch.object(bootstrap.time, "sleep") as sleep:
            self.run_helper()
        self.assertEqual(sleep.call_count, 2)
        self.tavern.calls.clear()
        self.password_file.write_text("wrong-password")
        _out, err = self.run_helper(expected=1)
        self.assertIn("HTTP 401", err)
        self.assertEqual(len(self.tavern.calls), 1)

    def test_readiness_timeout_is_bounded_and_sanitized(self):
        client = bootstrap.Client(self.tavern.endpoint, "linwhite", "password:with spaces ")
        self.tavern.startup_failures = 100
        with mock.patch.object(bootstrap.time, "monotonic", side_effect=[0, 0, 1]):
            with self.assertRaisesRegex(bootstrap.BootstrapError, "readiness timeout"):
                client.ready(1)
        self.assertEqual(len(self.tavern.calls), 1)
        self.assertEqual(self.tavern.writes(), [])

    def test_http_errors_invalid_json_and_redirects_do_not_expose_secrets(self):
        self.tavern.fail_path = "/version"
        _out, err = self.run_helper(expected=1)
        self.assertIn("HTTP 500", err)
        self.assertEqual(self.tavern.writes(), [])
        self.tavern.fail_path = None
        self.tavern.redirect_path = "/version"
        _out, err = self.run_helper(expected=1)
        self.assertIn("HTTP 302", err)
        self.assertNotIn("/do-not-follow", [path for _, path, _ in self.tavern.calls])
        client = bootstrap.Client(self.tavern.endpoint, "linwhite", "password:with spaces ")
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b'{"sk-bonsai-private": broken json}'
        with mock.patch.object(client.opener, "open", return_value=response):
            with self.assertRaisesRegex(bootstrap.BootstrapError, "Invalid API JSON response") as caught:
                client.request("/version")
        self.assertNotIn("sk-bonsai-private", str(caught.exception))
        with mock.patch.object(bootstrap, "bootstrap", side_effect=ValueError("sk-bonsai-private")):
            _out, err = self.run_helper(expected=1)
        self.assertIn("details suppressed", err)
        self.assertNotIn("Traceback", err)

    def test_incompatible_server_and_invalid_catalog_fail_before_writes(self):
        self.tavern.version = "1.17.0"
        self.run_helper(expected=1)
        self.assertEqual(self.tavern.writes(), [])
        self.tavern.version = "1.18.0"
        self.tavern.accounts = True
        self.run_helper(expected=1)
        self.assertEqual(self.tavern.writes(), [])
        self.tavern.accounts = False
        self.tavern.malformed_catalog = True
        self.run_helper(expected=1)
        self.assertEqual(self.tavern.writes(), [])

    def test_existing_user_profile_id_collision_is_not_adopted(self):
        self.tavern.settings["extension_settings"]["connectionManager"] = {
            "profiles": [{"id": "fleet-bonsai-hikari", "name": "User profile", "mode": "cc", "api": "custom"}],
            "selectedProfile": "fleet-bonsai-hikari",
        }
        before = copy.deepcopy(self.tavern.settings)
        self.run_helper(expected=1)
        self.assertEqual(self.tavern.settings, before)
        self.assertEqual(self.tavern.writes(), [])

    def test_user_preset_name_collision_is_not_adopted_or_overwritten(self):
        name = "Fleet - fleet-qwen-swift"
        self.tavern.presets[name] = {**copy.deepcopy(self.tavern.default), "custom_include_headers": "Authorization: private-user-key"}
        before = copy.deepcopy((self.tavern.settings, self.tavern.presets))
        self.run_helper(expected=1)
        self.assertEqual((self.tavern.settings, self.tavern.presets), before)
        self.assertEqual(self.tavern.writes(), [])

    def test_keyed_keyless_conversion_requires_new_id_not_a_preset_clobber(self):
        self.run_helper()
        before = copy.deepcopy((self.tavern.settings, self.tavern.presets, self.tavern.secrets))
        self.manifest["profiles"][0]["credential"] = None
        self.tavern.calls.clear()
        _out, err = self.run_helper(expected=1)
        self.assertIn("new profile ID", err)
        self.assertEqual((self.tavern.settings, self.tavern.presets, self.tavern.secrets), before)
        self.assertEqual(self.tavern.writes(), [])

    def test_manifest_validation_rejects_unsafe_or_mistyped_values(self):
        cases = [
            ("endpoint", "http://remote.invalid:8001"),
            ("endpoint", "http://password:sk-bonsai-private@127.0.0.1:8001"),
            ("endpoint", "http://127.0.0.1:8001/path"),
            ("username", "bad:name"), ("passwordFile", "relative"),
            ("readinessTimeoutSeconds", 0), ("readinessTimeoutSeconds", True),
            ("readinessTimeoutSeconds", float("inf")), ("unexpected", "secret"),
        ]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                manifest = copy.deepcopy(self.manifest)
                manifest[key] = value
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_manifest(manifest)
        for key, value in [("credential", "unknown"), ("context", True), ("maxTokens", 174080),
                           ("reasoningEffort", "none"), ("temperature", 3), ("topP", -1),
                           ("url", "http://host/v1?api_key=private"), ("id", "../escape"),
                           ("extra", "secret")]:
            with self.subTest(profile_field=key):
                manifest = copy.deepcopy(self.manifest)
                manifest["profiles"][0][key] = value
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_manifest(manifest)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "Invalid nested API JSON"):
            bootstrap.object_value("sk-bonsai-private not-json")
        self.assertEqual(self.tavern.calls, [])

    def test_missing_runtime_file_and_empty_file_errors_are_value_free(self):
        self.bonsai_file.unlink()
        _out, err = self.run_helper(expected=1)
        self.assertNotIn(str(self.bonsai_file), err)
        self.assertEqual(self.tavern.calls, [])
        self.bonsai_file.write_text("\n")
        self.run_helper(expected=1)
        self.assertEqual(self.tavern.calls, [])

    def test_pinned_source_oracle_confirms_profile_and_settings_aliases(self):
        manager = (SOURCE / "public/scripts/extensions/connection-manager/index.js").read_text()
        secret_server = (SOURCE / "src/endpoints/secrets.js").read_text()
        settings_server = (SOURCE / "src/endpoints/settings.js").read_text()
        presets_server = (SOURCE / "src/endpoints/presets.js").read_text()
        openai = (SOURCE / "public/scripts/openai.js").read_text()
        backend = (SOURCE / "src/endpoints/backends/chat-completions.js").read_text()
        self.assertIn("extension_settings.connectionManager", manager)
        self.assertIn("const mode = main_api === 'openai' ? 'cc' : 'tc';", manager)
        self.assertIn("'secret-id',", manager)
        self.assertIn("CUSTOM: 'api_key_custom'", secret_server)
        self.assertIn("const { key, value, label } = request.body;", secret_server)
        self.assertIn("return response.send({ id });", secret_server)
        self.assertIn("fileContents.push(file);", settings_server)
        self.assertIn("openai_setting_names", settings_server)
        self.assertIn("apiId", presets_server)
        self.assertIn("temperature: ['#temp_openai', 'temp_openai'", openai)
        self.assertIn("reasoning_effort: ['#openai_reasoning_effort', 'reasoning_effort'", openai)
        self.assertIn("mergeObjectWithYaml(bodyParams, request.body.custom_include_body);", backend)
        self.assertIn("readSecret(request.user.directories, SECRET_KEYS.CUSTOM, request.body.secret_id)", backend)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    args, unittest_args = parser.parse_known_args()
    SOURCE = args.source
    if not (SOURCE / "default/content/settings.json").is_file():
        parser.error("Upstream source oracle is unavailable; pass --source to the pinned 1.18.0 source")
    unittest.main(argv=[sys.argv[0], *unittest_args])
