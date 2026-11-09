#!/usr/bin/env python3
"""Provision SillyTavern 1.18.0 through its authenticated, CSRF-protected API.

Usage: python3 bootstrap.py MANIFEST.json

Manifest (unknown fields are rejected):
  endpoint: loopback HTTP origin, e.g. http://127.0.0.1:8001 (no path)
  username: HTTP Basic username, not a SillyTavern account handle
  passwordFile: absolute UTF-8 runtime credential path
  credentials: {name: absolute UTF-8 runtime credential path}
  defaultProfile: ID of a profile in profiles
  readinessTimeoutSeconds: optional, default 120, range 1..600
  basePreset: optional existing Chat Completion preset name; otherwise use the
    user's selected preset, falling back to the shipped Default via REST
  profiles: nonempty array of objects with:
    id: unique fleet-[a-z0-9-]+ ID (maximum 86 characters)
    name: unique display name
    url: OpenAI-compatible API base URL, including /v1 where needed
    model: initial model ID (users can select another model in the UI)
    context: context tokens, 512..2000000
    maxTokens: response tokens, 1..context-1
    credential: optional credentials name; absent/null means explicitly keyless
    reasoningEffort: optional auto/low/medium/high/min/max, default auto
    temperature: optional 0..2, default 0.8
    topP: optional 0..1, default 0.95

All profiles are Chat Completion / Custom, including Ollama's /v1 interface.
Presets are cloned from an API-returned preset, never from a vendored file.
Existing presets are NEVER overwritten. A missing managed preset is recreated
from its original seed, not from whichever preset the user now has selected.
Profile connection fields are updated together only while still unmodified;
renames, exclusions, preset choices and other user edits survive. A credential
rotation can repair an unmodified secret binding on a user-edited model, but
never on a user-edited endpoint. Old secrets/profiles/presets are not deleted.
Use a new profile ID when changing between keyed and keyless: existing presets
must retain their original Authorization behavior without being overwritten.

The default is selected only on the first successful provisioning of a pristine
user (firstRun=true, no profiles/selection). Existing users keep their choices.
A marker and non-secret seeds live in extension_settings.fleetBootstrap.
Credential labels include a password-keyed HMAC for idempotence and recovery;
no key exposure API is used. Harmless not-required secrets pin keyless profiles.
Keyless presets also override Authorization with Bearer not-required: upstream
Connection Manager changes URLs before rotating secrets, including /models
status requests. Keep presets bound to connections (the upstream default).
Keyed-to-keyed status requests have the same upstream ordering hazard; REST
settings alone cannot reorder it. Verify/fix that in browser integration.

Run once at service startup, before browser sessions; /api/settings/save is a
whole-document API with no atomic compare-and-swap. A final reread detects
concurrent edits, but cannot close the server's last read/save race. Serialize
helper invocations in systemd. Requires seeded user content and extensions;
keep enableUserAccounts=false and CSRF enabled. LoadCredential paths work
unchanged. Only Python's standard library is required; no upstream calls occur.
"""

import base64
import copy
import hashlib
import hmac
import http.cookiejar
import json
import math
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


SECRET_KEY = "api_key_custom"
MARKER = "fleetBootstrap"
VERSION = 1
KEYLESS_VALUE = "not-required"
PROFILE_ID = re.compile(r"fleet-[a-z0-9][a-z0-9-]{0,79}\Z")
CREDENTIAL_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
BINDING_FIELDS = ("mode", "api", "api-url", "model", "secret-id")
API_PATHS = {
    "/csrf-token", "/version", "/api/settings/get", "/api/settings/save",
    "/api/presets/restore", "/api/presets/save", "/api/secrets/read",
    "/api/secrets/write", "/api/secrets/rotate",
}


class BootstrapError(Exception):
    """Only constant, value-free messages may enter this exception."""


class APIError(BootstrapError):
    def __init__(self, path, status=None):
        # path is restricted to our constant allowlist, never a manifest value.
        super().__init__(f"API request failed: {path}" +
                         (f" (HTTP {status})" if status is not None else " (transport error)"))
        self.status = status


def require(condition, message):
    if not condition:
        raise BootstrapError(message)


def json_value(value):
    """The settings catalog contains JSON *strings* inside the outer JSON."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, RecursionError):
            raise BootstrapError("Invalid nested API JSON") from None
    return value


def object_value(value):
    value = json_value(value)
    require(isinstance(value, dict), "Expected an API JSON object")
    return value


def text(value):
    return (isinstance(value, str) and bool(value.strip()) and
            not any(ord(c) < 32 or ord(c) == 127 for c in value))


def number(value, low, high):
    return (type(value) in (int, float) and math.isfinite(value) and
            low <= value <= high)


def valid_url(value, loopback=False):
    if not text(value) or any(c.isspace() for c in value):
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
        parsed.port  # Validate malformed/out-of-range ports without logging them.
        if (parsed.scheme not in ("http", "https") or not parsed.hostname or
                parsed.username is not None or parsed.password is not None or
                parsed.query or parsed.fragment):
            return False
        if loopback:
            return (parsed.scheme == "http" and parsed.hostname in
                    ("127.0.0.1", "::1", "localhost") and parsed.path in ("", "/"))
        return True
    except ValueError:
        return False


def validate_manifest(value):
    require(isinstance(value, dict), "Manifest must be an object")
    allowed = {"endpoint", "username", "passwordFile", "credentials", "defaultProfile",
               "profiles", "readinessTimeoutSeconds", "basePreset"}
    require(not (value.keys() - allowed), "Unknown manifest field")
    require(valid_url(value.get("endpoint"), loopback=True), "Invalid loopback endpoint")
    require(text(value.get("username")) and ":" not in value["username"], "Invalid Basic username")
    for field in ("passwordFile",):
        require(text(value.get(field)) and Path(value[field]).is_absolute(), "Invalid credential path")
    credentials = value.get("credentials")
    require(isinstance(credentials, dict), "credentials must be an object")
    for name, path in credentials.items():
        require(bool(CREDENTIAL_NAME.fullmatch(name)), "Invalid credential name")
        require(text(path) and Path(path).is_absolute(), "Invalid credential path")
    require(number(value.get("readinessTimeoutSeconds", 120), 1, 600), "Invalid readiness timeout")
    if "basePreset" in value:
        require(text(value["basePreset"]), "Invalid base preset name")
    profiles = value.get("profiles")
    require(isinstance(profiles, list) and 1 <= len(profiles) <= 100, "Invalid profiles array")
    ids, names = set(), set()
    for profile in profiles:
        require(isinstance(profile, dict), "Invalid profile object")
        fields = {"id", "name", "url", "model", "credential", "context", "maxTokens",
                  "reasoningEffort", "temperature", "topP"}
        require(not (profile.keys() - fields), "Unknown profile field")
        require(text(profile.get("id")) and bool(PROFILE_ID.fullmatch(profile["id"])), "Invalid profile ID")
        require(text(profile.get("name")) and profile["name"] != "<None>", "Invalid profile name")
        require(profile["id"] not in ids and profile["name"].casefold() not in names, "Duplicate profile ID or name")
        ids.add(profile["id"])
        names.add(profile["name"].casefold())
        require(valid_url(profile.get("url")), "Invalid profile API base URL")
        require(text(profile.get("model")), "Invalid profile model")
        require(type(profile.get("context")) is int and 512 <= profile["context"] <= 2000000, "Invalid profile context")
        require(type(profile.get("maxTokens")) is int and 1 <= profile["maxTokens"] < profile["context"], "Invalid response length")
        credential = profile.get("credential")
        require(credential is None or (isinstance(credential, str) and credential in credentials), "Unknown profile credential")
        require(profile.get("reasoningEffort", "auto") in ("auto", "low", "medium", "high", "min", "max"), "Invalid reasoning effort")
        require(number(profile.get("temperature", 0.8), 0, 2), "Invalid temperature")
        require(number(profile.get("topP", 0.95), 0, 1), "Invalid topP")
    require(isinstance(value.get("defaultProfile"), str) and value["defaultProfile"] in ids, "Unknown default profile")
    return copy.deepcopy(value)


def read_credential(path):
    try:
        # Only strip file-terminating newlines, not intentional password spaces.
        value = Path(path).read_text(encoding="utf-8").rstrip("\r\n")
    except (OSError, UnicodeError):
        raise BootstrapError("Cannot read runtime credential file") from None
    require(text(value), "Runtime credential is empty or contains control characters")
    return value


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, endpoint, username, password):
        self.endpoint = endpoint.rstrip("/")
        self.authorization = "Basic " + base64.b64encode(
            f"{username}:{password}".encode("utf-8")).decode("ascii")
        self.token = None
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirects(),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, body=None, timeout=10):
        require(path in API_PATHS, "Disallowed API operation")
        headers = {"Authorization": self.authorization, "Accept": "application/json"}
        if self.token is not None:
            headers["X-CSRF-Token"] = self.token
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.endpoint + path, data=data, headers=headers)
        try:
            with self.opener.open(request, timeout=timeout) as response:
                if response.status == 204:
                    return None
                raw = response.read(32 * 1024 * 1024 + 1)
                require(len(raw) <= 32 * 1024 * 1024, "API response too large")
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()  # Never read/log error bodies or reason phrases.
            raise APIError(path, status) from None
        except (OSError, urllib.error.URLError, ValueError):
            raise APIError(path) from None
        try:
            return json.loads(raw)
        except (ValueError, UnicodeError, RecursionError):
            raise BootstrapError("Invalid API JSON response") from None

    def ready(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            try:
                token = object_value(self.request("/csrf-token", timeout=min(10, max(0.01, deadline - time.monotonic())))).get("token")
                require(text(token), "Missing CSRF token")
                self.token = token
                return object_value(self.request("/api/settings/get", {}, timeout=min(10, max(0.01, deadline - time.monotonic()))))
            except APIError as error:
                if error.status is not None and error.status not in (500, 502, 503, 504):
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BootstrapError("SillyTavern readiness timeout") from None
                time.sleep(min(1, remaining))


def catalog_presets(catalog):
    names, values = catalog.get("openai_setting_names"), catalog.get("openai_settings")
    require(isinstance(names, list) and isinstance(values, list) and len(names) == len(values), "Invalid Chat Completion preset catalog")
    require(all(text(name) for name in names) and len(set(names)) == len(names), "Invalid preset catalog names")
    return {name: object_value(value) for name, value in zip(names, values)}


def preset_name(profile_id):
    # Fixed ASCII names cannot be transformed by upstream sanitize-filename.
    return "Fleet - " + profile_id


def make_preset(template, spec):
    preset = copy.deepcopy(template)
    effort = spec.get("reasoningEffort", "auto")
    preset.update({
        "chat_completion_source": "custom", "custom_url": spec["url"].rstrip("/"),
        "custom_model": spec["model"], "reverse_proxy": "", "proxy_password": "",
        "custom_include_headers": json.dumps({"Authorization": "Bearer " + KEYLESS_VALUE}) if spec.get("credential") is None else "",
        "custom_exclude_body": "",
        # 1.18 only forwards native effort for recognized OpenAI model names.
        # JSON is valid YAML for the supported Custom additional-body setting.
        "custom_include_body": json.dumps({"reasoning_effort": effort}) if effort != "auto" else "",
        "custom_prompt_post_processing": "", "reasoning_effort": effort,
        "show_thoughts": True, "openai_max_context": spec["context"],
        "openai_max_tokens": spec["maxTokens"], "max_context_unlocked": True,
        "temperature": spec.get("temperature", 0.8), "top_p": spec.get("topP", 0.95),
        "frequency_penalty": 0, "presence_penalty": 0,
        "stream_openai": True, "n": 1,
    })
    return preset


def owned_preset(preset, profile_id):
    extensions = preset.get("extensions", {})
    return (isinstance(extensions, dict) and
            extensions.get(MARKER) == {"version": VERSION, "profileId": profile_id})


def make_profile(spec, secret_id):
    return {"id": spec["id"], "name": spec["name"], "mode": "cc", "api": "custom",
            "api-url": spec["url"].rstrip("/"), "model": spec["model"],
            "secret-id": secret_id, "preset": preset_name(spec["id"]),
            "proxy": "None", "prompt-post-processing": "none", "exclude": []}


def merge_profile(current, previous, desired, same_credential):
    """Atomic connection update; three-way merge of non-connection fields."""
    merged, baseline = copy.deepcopy(current), copy.deepcopy(previous)
    untouched = all(current.get(key) == previous.get(key) for key in BINDING_FIELDS)
    if untouched:
        for key in BINDING_FIELDS:
            merged[key] = baseline[key] = desired[key]
    elif (same_credential and current.get("mode") == "cc" and current.get("api") == "custom" and
          current.get("api-url") == previous.get("api-url") == desired.get("api-url") and
          current.get("secret-id") == previous.get("secret-id")):
        merged["secret-id"] = baseline["secret-id"] = desired["secret-id"]
    for key in desired.keys() - set(BINDING_FIELDS):
        if current.get(key) == previous.get(key):
            merged[key] = baseline[key] = copy.deepcopy(desired[key])
    return merged, baseline, untouched


def secret_states(value):
    states = object_value(value).get(SECRET_KEY)
    require(states is None or isinstance(states, list), "Invalid Custom secret catalog")
    states = states or []
    for state in states:
        require(isinstance(state, dict) and text(state.get("id")) and
                isinstance(state.get("label"), str) and type(state.get("active")) is bool, "Invalid Custom secret state")
    require(len({state["id"] for state in states}) == len(states), "Duplicate Custom secret IDs")
    require(sum(state["active"] for state in states) <= 1, "Multiple active Custom secrets")
    return states


def ensure_secret(client, states, label, value):
    matches = [state for state in states if state["label"] == label]
    require(len(matches) <= 1, "Ambiguous managed secret label")
    if matches:
        return matches[0]["id"]
    result = object_value(client.request("/api/secrets/write", {"key": SECRET_KEY, "value": value, "label": label}))
    secret_id = result.get("id")
    try:
        uuid.UUID(secret_id)
    except (ValueError, TypeError, AttributeError):
        raise BootstrapError("Invalid secret-write ID") from None
    states.append({"id": secret_id, "label": label, "active": False})
    return secret_id


def bootstrap(client, manifest, password, credentials):
    catalog = client.ready(manifest.get("readinessTimeoutSeconds", 120))
    require(catalog.get("enable_accounts") is False, "Bootstrap requires disabled user accounts")
    require(catalog.get("enable_extensions") is True, "Bootstrap requires server extensions")
    version = object_value(client.request("/version")).get("pkgVersion")
    require(version == "1.18.0", "Bootstrap requires SillyTavern 1.18.0")
    original = object_value(catalog.get("settings"))
    settings = copy.deepcopy(original)
    extension = settings.setdefault("extension_settings", {})
    require(isinstance(extension, dict), "Invalid extension settings")
    manager = extension.setdefault("connectionManager", {"profiles": [], "selectedProfile": None})
    require(isinstance(manager, dict) and isinstance(manager.get("profiles", []), list), "Invalid connection manager settings")
    profiles = manager.setdefault("profiles", [])
    require(all(isinstance(profile, dict) and text(profile.get("id")) for profile in profiles), "Invalid existing connection profile")
    require(len({profile["id"] for profile in profiles}) == len(profiles), "Duplicate existing profile IDs")
    first = MARKER not in extension
    select_default = first and original.get("firstRun") is True and not profiles and not manager.get("selectedProfile")
    marker = extension.setdefault(MARKER, {"version": VERSION, "profiles": {}})
    require(isinstance(marker, dict) and marker.get("version") == VERSION and isinstance(marker.get("profiles"), dict), "Unsupported bootstrap state")
    records = marker["profiles"]
    presets = catalog_presets(catalog)
    template_name = manifest.get("basePreset", settings.get("oai_settings", {}).get("preset_settings_openai", "Default"))
    if "basePreset" in manifest:
        require(template_name in presets, "Requested base preset is absent")
    template = presets.get(template_name)
    if template is None:
        restored = object_value(client.request("/api/presets/restore", {"apiId": "openai", "name": "Default"}))
        require(restored.get("isDefault") is True, "Shipped Default preset is unavailable")
        template = object_value(restored.get("preset"))
    require(bool(template), "Base preset is empty")

    # Validate ownership before writing any secrets or presets.
    by_id = {profile["id"]: profile for profile in profiles}
    for spec in manifest["profiles"]:
        profile_id = spec["id"]
        require(profile_id not in by_id or profile_id in records, "Managed profile ID collides with an existing user profile")
        if profile_id in records:
            require(isinstance(records[profile_id], dict) and isinstance(records[profile_id].get("profile"), dict) and
                    isinstance(records[profile_id].get("preset"), dict), "Invalid managed profile state")
            require((records[profile_id].get("credential") is None) == (spec.get("credential") is None),
                    "Changing keyed/keyless mode requires a new profile ID")
        else:
            existing = presets.get(preset_name(profile_id))
            require(existing is None or owned_preset(existing, profile_id),
                    "Managed preset name collides with an existing user preset")
        require(not any(profile.get("name", "").casefold() == spec["name"].casefold() and profile["id"] != profile_id for profile in profiles), "Managed profile name collides with a user profile")

    states = secret_states(client.request("/api/secrets/read", {}))
    original_active = next((state["id"] for state in states if state["active"]), None)
    restore_active = original_active
    try:
        if original_active is None:
            # Importing keys must not turn a previously keyless live connection
            # into an authenticated one, even if provisioning later fails.
            restore_active = ensure_secret(client, states, "Fleet bootstrap / previously keyless", KEYLESS_VALUE)
        credential_ids = {}
        for name, value in credentials.items():
            digest = hmac.new(password.encode("utf-8"), (name + "\0" + value).encode("utf-8"), hashlib.sha256).hexdigest()
            label = f"Fleet bootstrap / credential / {name} / {digest}"
            credential_ids[name] = ensure_secret(client, states, label, value)
        default_secret = None
        for spec in manifest["profiles"]:
            profile_id = spec["id"]
            credential = spec.get("credential")
            secret_id = credential_ids[credential] if credential is not None else ensure_secret(
                client, states, f"Fleet bootstrap / keyless / {profile_id}", KEYLESS_VALUE)
            desired = make_profile(spec, secret_id)
            record = records.get(profile_id)
            if record is None:
                # Recover a marked preset left by an interrupted first settings
                # save, keeping its original prompt/template choices.
                seed = copy.deepcopy(presets.get(desired["preset"]))
                if seed is None:
                    seed = make_preset(template, spec)
                    seed_extensions = seed.setdefault("extensions", {})
                    require(isinstance(seed_extensions, dict), "Invalid base preset extensions")
                    seed_extensions[MARKER] = {"version": VERSION, "profileId": profile_id}
                record = {"profile": copy.deepcopy(desired), "preset": seed, "credential": credential}
                records[profile_id] = record
            current = by_id.get(profile_id)
            old = copy.deepcopy(record["profile"])
            if current is None:
                current = copy.deepcopy(desired)
                profiles.append(current)
                by_id[profile_id] = current
                record["profile"] = copy.deepcopy(desired)
                record["credential"] = credential
            else:
                merged, baseline, untouched = merge_profile(current, old, desired, record.get("credential") == credential)
                current.clear()
                current.update(merged)
                record["profile"] = baseline
                if untouched:
                    record["credential"] = credential
            if (original_active == old.get("secret-id") and current.get("secret-id") == secret_id and
                    settings.get("main_api") == "openai" and
                    settings.get("oai_settings", {}).get("chat_completion_source") == "custom" and
                    settings.get("oai_settings", {}).get("custom_url") == current.get("api-url")):
                restore_active = secret_id
            name = desired["preset"]
            # Never overwrite a preset, including an unmarked same-name preset.
            # Do not recreate an old preset after the user chose/renamed another.
            if current.get("preset") == name and name not in presets:
                result = object_value(client.request("/api/presets/save", {"apiId": "openai", "name": name, "preset": record["preset"]}))
                require(result.get("name") == name, "Preset save returned a different name")
                presets[name] = copy.deepcopy(record["preset"])
            if profile_id == manifest["defaultProfile"]:
                default_secret = secret_id
                if select_default:
                    manager["selectedProfile"] = profile_id
                    settings["main_api"] = "openai"
                    oai = settings.setdefault("oai_settings", {})
                    require(isinstance(oai, dict), "Invalid Chat Completion settings")
                    # Preserve original prompts/formatting; only apply the small
                    # connection/sampling delta, with upstream's sampler aliases.
                    delta = make_preset({}, spec)
                    aliases = {"temperature": "temp_openai", "top_p": "top_p_openai",
                               "frequency_penalty": "freq_pen_openai", "presence_penalty": "pres_pen_openai",
                               "top_k": "top_k_openai", "top_a": "top_a_openai",
                               "min_p": "min_p_openai", "repetition_penalty": "repetition_penalty_openai"}
                    for key, value in presets[current["preset"]].items():
                        oai.setdefault(aliases.get(key, key), copy.deepcopy(value))
                    oai.update({aliases.get(key, key): value for key, value in delta.items()})
                    oai["preset_settings_openai"] = current["preset"]

        if settings != original:
            latest = object_value(client.request("/api/settings/get", {})).get("settings")
            require(object_value(latest) == original, "Settings changed concurrently; rerun bootstrap before opening the UI")
            saved = object_value(client.request("/api/settings/save", settings))
            require(saved.get("result") == "ok", "Settings save did not acknowledge success")
        if select_default:
            restore_active = default_secret
    finally:
        # write auto-activates each new secret. Restore the user's active key
        # even after partial failure; only first provisioning selects a default.
        if restore_active is not None:
            live = secret_states(client.request("/api/secrets/read", {}))
            if not any(state["id"] == restore_active and state["active"] for state in live):
                client.request("/api/secrets/rotate", {"key": SECRET_KEY, "id": restore_active})


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("Usage: bootstrap.py MANIFEST.json", file=sys.stderr)
        return 2
    try:
        try:
            value = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError, RecursionError):
            raise BootstrapError("Cannot read JSON manifest") from None
        manifest = validate_manifest(value)
        password = read_credential(manifest["passwordFile"])
        credentials = {name: read_credential(path) for name, path in manifest["credentials"].items()}
        client = Client(manifest["endpoint"], manifest["username"], password)
        bootstrap(client, manifest, password, credentials)
    except BootstrapError as error:
        print(f"SillyTavern bootstrap: {error}", file=sys.stderr)
        return 1
    except Exception:
        # No traceback: unexpected exceptions can contain headers/body values.
        print("SillyTavern bootstrap: unexpected failure (details suppressed)", file=sys.stderr)
        return 1
    print("SillyTavern bootstrap complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
