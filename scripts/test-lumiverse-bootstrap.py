#!/usr/bin/env python3
"""Offline contract tests against an isolated loopback REST fixture; no upstream calls.

Run: python3 scripts/test-lumiverse-bootstrap.py
The fixture follows Lumiverse 1.2.5 routes, CreateConnectionProfileInput,
PaginatedResult, settings envelopes and Better Auth's native cookie login.
It is not a substitute for testing the pinned server/browser at deployment.
"""

import contextlib
import copy
import importlib.util
import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("lumiverse_bootstrap", ROOT / "system/modules/lumiverse/bootstrap.py")
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)
PASSWORD = "isolated-fixture-password"
COOKIE = "fixture-secret-session"
ORIGIN = "http://seraph.inner.imdomestic.com:7861"


class Fixture:
    def __init__(self):
        self.profiles = []
        self.settings = {}
        self.requests = []
        self.failure = None
        self.failure_status = 500
        self.role = "owner"
        self.next_id = 1
        self.page_size = 1
        self.chats = [{"id": "untouched-chat", "messages": ["unchanged"]}]
        self.presets = [{"id": "native-default", "prompts": {"user-edited": True}}]

    def dispatch(self, method, path, headers, body):
        self.requests.append((method, path, body))
        assert headers["Host"] == "seraph.inner.imdomestic.com:7861"
        assert headers["Origin"] == ORIGIN
        if self.failure in (path, (method, path)):
            return self.failure_status, {"error": PASSWORD + COOKIE + "upstream-secret"}, {
                "Location": "http://forbidden.invalid/credential-leak",
            }
        if path == "/api/auth/sign-in/username":
            assert method == "POST"
            assert body == {"username": "linwhite", "password": PASSWORD}
            return 200, {"user": {"username": "linwhite"}}, {
                "Set-Cookie": f"better-auth.session_token={COOKIE}; Path=/; HttpOnly; SameSite=Lax",
            }
        assert headers.get("Cookie") == f"better-auth.session_token={COOKIE}"
        if path == "/api/auth/get-session":
            assert method == "GET"
            return 200, {"user": {"username": "linwhite", "role": self.role}}, {}
        if path == "/api/auth/sign-out":
            assert method == "POST"
            return 200, {"success": True}, {}
        url = urlsplit(path)
        if url.path == "/api/v1/connections":
            if method == "GET":
                query = parse_qs(url.query)
                offset = int(query["offset"][0])
                assert query["limit"] == ["200"]
                return 200, {"data": self.profiles[offset:offset + self.page_size],
                             "total": len(self.profiles), "offset": offset, "limit": self.page_size}, {}
            assert method == "POST"
            assert set(body) == {"name", "provider", "api_url", "model", "api_key", "is_default", "metadata"}
            assert body["provider"] == "custom"
            assert body["api_key"] == "not-required"
            assert "rewind" not in body["model"].casefold()
            assert body["api_url"] in bootstrap.BASE_URLS
            if body["is_default"]:
                for profile in self.profiles:
                    profile["is_default"] = False
            profile = {key: value for key, value in body.items() if key != "api_key"}
            profile.update(id=f"server-uuid-{self.next_id}", has_api_key=True,
                           preset_id=None, created_at=1234, updated_at=1234)
            self.next_id += 1
            self.profiles.append(profile)
            return 201, profile, {}
        if url.path.startswith("/api/v1/settings/"):
            key = url.path.removeprefix("/api/v1/settings/")
            assert key in {bootstrap.STATE_KEY, "activeProfileId"}
            if method == "PUT":
                assert set(body) == {"value"}
                self.settings[key] = body["value"]
            else:
                assert method == "GET"
            if key not in self.settings:
                return 404, {"error": "Not found"}, {}
            return 200, {"key": key, "value": self.settings[key], "updated_at": 1234}, {}
        raise AssertionError("Unexpected API path (catalog/test/generation calls are forbidden)")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def handle_request(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            status, value, headers = self.server.fixture.dispatch(
                self.command, self.path, self.headers, json.loads(body) if body else None)
        except AssertionError as error:
            self.server.fixture_errors.append(str(error) or "REST contract assertion failed")
            status, value, headers = 400, {"error": "fixture assertion failed"}, {}
        encoded = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    do_GET = handle_request
    do_POST = handle_request
    do_PUT = handle_request


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.password_file = Path(self.temp.name) / "credential"
        self.password_file.write_text(PASSWORD + "\n")
        self.fixture = Fixture()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.fixture = self.fixture
        self.server.fixture_errors = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.manifest = {
            "endpoint": f"http://127.0.0.1:{self.server.server_port}", "origin": ORIGIN,
            "username": "linwhite", "passwordFile": str(self.password_file),
            "defaultConnection": "bonsai", "connections": [
                {"id": "cli", "name": "CLIProxy", "provider": "custom",
                 "baseUrl": "http://127.0.0.1:8002/cliproxy/v1", "defaultModel": "allowed-fixture-model"},
                {"id": "bonsai", "name": "Bonsai Hikari", "provider": "custom",
                 "baseUrl": "http://127.0.0.1:8002/bonsai/v1", "defaultModel": "fixture-hikari"},
                {"id": "qwen", "name": "Qwen (offline)", "provider": "custom",
                 "baseUrl": "http://taipan.inner.imdomestic.com:8000/v1", "defaultModel": "fixture-qwen"},
            ],
        }

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.temp.cleanup()
        self.assertEqual(self.server.fixture_errors, [])

    def test_first_run_exact_native_schema_and_default(self):
        before = copy.deepcopy((self.fixture.chats, self.fixture.presets))
        self.assertEqual(bootstrap.run(self.manifest), 3)
        default = self.fixture.profiles[0]
        self.assertEqual(default["name"], "Bonsai Hikari")
        self.assertTrue(default["is_default"])
        self.assertEqual(default["model"], "fixture-hikari")
        self.assertEqual(self.fixture.settings["activeProfileId"], default["id"])
        self.assertEqual(len(self.fixture.settings[bootstrap.STATE_KEY]["connections"]), 3)
        self.assertEqual((self.fixture.chats, self.fixture.presets), before)
        self.assertEqual(self.fixture.requests[-1][1], "/api/auth/sign-out")

    def test_rerun_preserves_all_user_edits_and_defaults(self):
        bootstrap.run(self.manifest)
        self.fixture.profiles[0].update(name="My edited name", model="my-model", api_url="http://edited.invalid", is_default=False)
        self.fixture.profiles[0]["metadata"] = {"user": "removed bootstrap marker"}
        self.fixture.profiles[1]["is_default"] = True
        self.fixture.settings["activeProfileId"] = self.fixture.profiles[1]["id"]
        before = copy.deepcopy((self.fixture.profiles, self.fixture.settings))
        self.manifest["connections"][1]["defaultModel"] = "new-declared-default"
        self.fixture.requests.clear()
        self.assertEqual(bootstrap.run(self.manifest), 0)
        self.assertEqual((self.fixture.profiles, self.fixture.settings), before)
        self.assertFalse(any(method == "PUT" or path == "/api/v1/connections"
                             for method, path, _ in self.fixture.requests))
        self.assertIn("/api/v1/connections?limit=200&offset=2", [r[1] for r in self.fixture.requests])

    def test_deleted_profiles_are_not_resurrected(self):
        bootstrap.run(self.manifest)
        self.fixture.profiles.clear()
        self.fixture.settings["activeProfileId"] = None
        self.assertEqual(bootstrap.run(self.manifest), 0)
        self.assertEqual(self.fixture.profiles, [])
        self.assertIsNone(self.fixture.settings["activeProfileId"])

    def test_existing_user_default_is_not_changed(self):
        self.fixture.profiles.append({"id": "personal", "metadata": {}, "is_default": True})
        self.fixture.settings["activeProfileId"] = "personal"
        self.assertEqual(bootstrap.run(self.manifest), 3)
        self.assertEqual([p["id"] for p in self.fixture.profiles if p["is_default"]], ["personal"])
        self.assertEqual(self.fixture.settings["activeProfileId"], "personal")

    def test_missing_default_on_nonpristine_account_is_preserved(self):
        self.fixture.settings["activeProfileId"] = None
        bootstrap.run(self.manifest)
        self.assertFalse(any(p["is_default"] for p in self.fixture.profiles))
        self.assertIsNone(self.fixture.settings["activeProfileId"])

    def test_recovery_after_post_before_ledger(self):
        self.fixture.failure = ("PUT", f"/api/v1/settings/{bootstrap.STATE_KEY}")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.run(self.manifest)
        self.assertEqual(len(self.fixture.profiles), 1)
        recovered_id = self.fixture.profiles[0]["id"]
        self.fixture.failure = None
        self.assertEqual(bootstrap.run(self.manifest), 2)
        self.assertEqual(self.fixture.settings[bootstrap.STATE_KEY]["connections"]["bonsai"], recovered_id)
        self.assertEqual(sum(p["metadata"].get(bootstrap.MARKER) == "bonsai" for p in self.fixture.profiles), 1)

    def test_forbidden_model_rejected_before_login(self):
        for model in ("rewind/model", "ReWiNd/model", "provider/rewind/model"):
            with self.subTest(model=model):
                manifest = copy.deepcopy(self.manifest)
                manifest["connections"][-1]["defaultModel"] = model
                with self.assertRaisesRegex(bootstrap.BootstrapError, "Rewind is forbidden"):
                    bootstrap.run(manifest)
        self.assertEqual(self.fixture.requests, [])

    def test_invalid_schema_and_secret_fields_rejected_before_login(self):
        for field, value in (("models", ["rewind/model"]), ("api_key", "must-not-use"), ("parameters", {})):
            with self.subTest(field=field):
                manifest = copy.deepcopy(self.manifest)
                manifest["connections"][0][field] = value
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.run(manifest)
        self.assertEqual(self.fixture.requests, [])

    def test_endpoint_restrictions(self):
        for endpoint in ("http://example.org:7860", "http://127.0.0.1:7860/path", "http://user:pass@127.0.0.1:7860"):
            manifest = copy.deepcopy(self.manifest)
            manifest["endpoint"] = endpoint
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.run(manifest)
        self.manifest["connections"][0]["baseUrl"] = "http://rewind.invalid/v1"
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.run(self.manifest)
        self.assertEqual(self.fixture.requests, [])

    def test_requires_expected_owner_role(self):
        self.fixture.role = "admin"
        with self.assertRaisesRegex(bootstrap.BootstrapError, "expected owner"):
            bootstrap.run(self.manifest)
        self.assertEqual(self.fixture.profiles, [])

    def test_error_redaction_no_traceback_or_response_body(self):
        manifest_file = Path(self.temp.name) / "manifest.json"
        manifest_file.write_text(json.dumps(self.manifest))
        self.fixture.failure = "/api/auth/sign-in/username"
        output = io.StringIO()
        with contextlib.redirect_stderr(output), contextlib.redirect_stdout(output):
            self.assertEqual(bootstrap.main([str(manifest_file)]), 1)
        self.assertIn("HTTP 500", output.getvalue())
        for secret in (PASSWORD, COOKIE, "upstream-secret", "Traceback"):
            self.assertNotIn(secret, output.getvalue())

    def test_redirects_are_rejected_not_followed(self):
        self.fixture.failure = "/api/auth/sign-in/username"
        self.fixture.failure_status = 302
        with self.assertRaisesRegex(bootstrap.BootstrapError, "HTTP 302"):
            bootstrap.run(self.manifest)
        self.assertEqual(len(self.fixture.requests), 1)

    def test_transport_errors_are_redacted(self):
        with patch.object(bootstrap.http.client.HTTPConnection, "request", side_effect=OSError(PASSWORD + COOKIE)):
            with self.assertRaises(bootstrap.BootstrapError) as caught:
                bootstrap.run(self.manifest)
        self.assertEqual(str(caught.exception), "Lumiverse transport or JSON response failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
