#!/usr/bin/env python3
"""Create-only native REST bootstrap for Lumiverse 1.2.5 (45f8db563e1c).

Usage: python3 bootstrap.py manifest.json
Manifest: {endpoint, origin, username, passwordFile, defaultConnection,
           connections: [{id, name, provider: "custom", baseUrl, defaultModel}]}
IDs are stable manifest keys, NOT server UUIDs. Run serially, before UI use.
Connection profiles save model selections; native Loom prompt presets are left
alone. Catalogs remain dynamic: no supported static `models` field exists.
This is not a runtime Rewind guard; filtering/blocking belongs on the server.
"""

import http.client
from http.cookies import SimpleCookie
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit


STATE_KEY = "nixLumiverseBootstrap"
MARKER = "nixLumiverseBootstrapId"
BASE_URLS = {
    "http://127.0.0.1:8002/cliproxy/v1",
    "http://127.0.0.1:8002/bonsai/v1",
    "http://taipan.inner.imdomestic.com:8000/v1",
    "http://h610.inner.imdomestic.com:11435/v1",
    "http://tank.inner.imdomestic.com:11434/v1",
}


class BootstrapError(Exception):
    """Messages must never contain server bodies, credentials or input values."""


def require(condition, message):
    if not condition:
        raise BootstrapError(message)


def text(value):
    return isinstance(value, str) and bool(value) and not any(ord(c) < 32 for c in value)


def validate(manifest):
    require(isinstance(manifest, dict), "Manifest must be an object")
    require(set(manifest) == {
        "endpoint", "origin", "username", "passwordFile", "defaultConnection", "connections",
    }, "Manifest fields do not match the supported schema")
    for key in ("endpoint", "origin", "username", "passwordFile", "defaultConnection"):
        require(text(manifest[key]), "Manifest string field is invalid")
    for key in ("endpoint", "origin"):
        try:
            url = urlsplit(manifest[key])
            valid = (url.scheme == "http" and url.hostname and url.port != 0
                     and not url.username and not url.password and not url.path
                     and not url.query and not url.fragment)
        except ValueError:
            valid = False
        require(valid, "Endpoint and origin must be plain HTTP origins")
    require(urlsplit(manifest["endpoint"]).hostname in {"127.0.0.1", "::1"},
            "Endpoint must use a loopback IP")
    require(Path(manifest["passwordFile"]).is_absolute(), "passwordFile must be absolute")
    connections = manifest["connections"]
    require(isinstance(connections, list) and bool(connections), "connections must be a nonempty list")
    ids = set()
    for connection in connections:
        require(isinstance(connection, dict) and set(connection) == {
            "id", "name", "provider", "baseUrl", "defaultModel",
        }, "Connection fields do not match the supported schema (models is not supported)")
        require(all(text(value) for value in connection.values()), "Connection string field is invalid")
        require(re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", connection["id"]) is not None,
                "Connection id must be a stable lowercase key")
        require(connection["id"] not in ids, "Duplicate connection id")
        ids.add(connection["id"])
        require(connection["provider"] == "custom", "Only the native custom provider is supported")
        require(connection["baseUrl"] in BASE_URLS, "Connection endpoint is not approved")
        # Reject instead of silently dropping a requested forbidden selection.
        require("rewind" not in " ".join(connection.values()).casefold(), "Rewind is forbidden")
    require(manifest["defaultConnection"] in ids, "defaultConnection must identify a connection")
    return manifest


class Client:
    """Loopback-only HTTP, external Host/Origin, in-memory cookies, no redirects."""

    def __init__(self, manifest):
        self.endpoint = urlsplit(manifest["endpoint"])
        self.origin = manifest["origin"]
        self.cookies = {}

    def request(self, method, path, body=None, missing=False):
        connection = http.client.HTTPConnection(self.endpoint.hostname, self.endpoint.port, timeout=30)
        headers = {"Host": urlsplit(self.origin).netloc, "Origin": self.origin,
                   "Accept": "application/json", "Content-Type": "application/json"}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in self.cookies.items())
        try:
            connection.request(method, path, body=None if body is None else json.dumps(body), headers=headers)
            response = connection.getresponse()
            if response.status == 404 and missing:
                return None
            require(200 <= response.status < 300, f"Lumiverse request failed (HTTP {response.status})")
            raw = response.read(4 * 1024 * 1024 + 1)
            require(len(raw) <= 4 * 1024 * 1024, "Lumiverse response exceeds limit")
            for key, value in response.getheaders():
                if key.lower() == "set-cookie":
                    cookie = SimpleCookie()
                    cookie.load(value)
                    for name, morsel in cookie.items():
                        self.cookies[name] = morsel.value
            return json.loads(raw)
        except BootstrapError:
            raise
        except (OSError, ValueError, http.client.HTTPException):
            raise BootstrapError("Lumiverse transport or JSON response failed") from None
        finally:
            connection.close()

    def login(self, username, password):
        self.request("POST", "/api/auth/sign-in/username", {"username": username, "password": password})
        session = self.request("GET", "/api/auth/get-session")
        user = session.get("user", {}) if isinstance(session, dict) else {}
        require(isinstance(user, dict) and user.get("username") == username.lower()
                and user.get("role") == "owner", "Login did not resolve to the expected owner")

    def setting(self, key):
        result = self.request("GET", f"/api/v1/settings/{key}", missing=True)
        require(result is None or isinstance(result, dict) and "value" in result,
                "Unexpected setting response")
        return result

    def profiles(self):
        rows = []
        while True:
            page = self.request("GET", f"/api/v1/connections?limit=200&offset={len(rows)}")
            require(isinstance(page, dict) and isinstance(page.get("data"), list)
                    and type(page.get("total")) is int, "Unexpected connection list response")
            rows.extend(page["data"])
            if len(rows) >= page["total"]:
                return rows
            require(bool(page["data"]), "Incomplete connection list response")


def provision(client, manifest):
    profiles = client.profiles()
    require(all(isinstance(row, dict) and text(row.get("id"))
                and isinstance(row.get("metadata"), dict) for row in profiles),
            "Unexpected connection profile response")
    saved = client.setting(STATE_KEY)
    state = saved["value"] if saved is not None else {"version": 1, "connections": {}}
    require(isinstance(state, dict) and state.get("version") == 1
            and isinstance(state.get("connections"), dict)
            and all(text(k) and text(v) for k, v in state["connections"].items()),
            "Unexpected bootstrap ledger")
    known = state["connections"]
    active = client.setting("activeProfileId")
    pristine = not profiles and saved is None and active is None
    created = 0
    # Default first: a partial run never leaves another profile as the default.
    ordered = sorted(manifest["connections"], key=lambda c: c["id"] != manifest["defaultConnection"])
    for item in ordered:
        key = item["id"]
        if key in known:
            continue  # Includes user-deleted profiles: never resurrect them.
        matches = [row for row in profiles if row["metadata"].get(MARKER) == key]
        require(len(matches) <= 1, "Ambiguous bootstrap connection markers")
        if matches:
            profile = matches[0]  # Recover a POST whose ledger update was interrupted.
        else:
            is_default = pristine and key == manifest["defaultConnection"]
            profile = client.request("POST", "/api/v1/connections", {
                "name": item["name"], "provider": item["provider"],
                "api_url": item["baseUrl"], "model": item["defaultModel"],
                "api_key": "not-required", "is_default": is_default,
                "metadata": {MARKER: key},
            })
            require(isinstance(profile, dict) and text(profile.get("id")),
                    "Unexpected created connection response")
            created += 1
            if is_default:
                client.request("PUT", "/api/v1/settings/activeProfileId", {"value": profile["id"]})
        known[key] = profile["id"]
        client.request("PUT", f"/api/v1/settings/{STATE_KEY}", {"value": state})
    return created


def run(manifest):
    validate(manifest)  # Validate everything before reading credentials or making requests.
    try:
        password = Path(manifest["passwordFile"]).read_text().rstrip("\r\n")
    except (OSError, UnicodeError):
        raise BootstrapError("Could not read passwordFile") from None
    require(8 <= len(password) <= 128, "Password file does not satisfy native password length limits")
    client = Client(manifest)
    try:
        client.login(manifest["username"], password)
        return provision(client, manifest)
    finally:
        if client.cookies:
            try:
                client.request("POST", "/api/auth/sign-out", {})
            except BootstrapError:
                pass
            client.cookies.clear()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("Usage: bootstrap.py manifest.json", file=sys.stderr)
        return 2
    try:
        manifest = json.loads(Path(argv[0]).read_text())
        count = run(manifest)
    except BootstrapError as error:
        print(f"Lumiverse bootstrap: {error}", file=sys.stderr)
        return 1
    except Exception:
        # Even unexpected failures must not dump request data or response bodies.
        print("Lumiverse bootstrap: input or response could not be processed", file=sys.stderr)
        return 1
    print(f"Lumiverse bootstrap: created {count} connection(s); existing user data preserved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
