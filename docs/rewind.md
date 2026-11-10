# Rewind provider for CLIProxyAPI

`pkgs/cliproxy-rewind/` builds a C ABI shared library for CLIProxyAPI 8. The
plugin owns Rewind authentication and declares native Responses input and
output. CLIProxyAPI still owns client authentication, credential selection and
usage collection. The Rewind executor requires native `/v1/responses`; ordinary
Chat Completions requests are not supported.

The fleet enables it on gizmo through `services.cliproxy.rewind`. Its models
use the `rewind/` prefix, kept separate from the existing unprefixed Codex
models. The upstream controls what each alias resolves to; the plugin
preserves the upstream response's `model` field.

## Usage conditions {#usage-conditions}

Rewind is a **conditional-use model provider**, marked `conditional = true` in
`lib/cliproxy-models.nix`. Its actual eligibility and usage terms must be
confirmed with the provider or administrator before separate use. A model's
presence in discovery, or possession of the fleet's CLIProxy client key, does
not establish that its usage conditions have been satisfied or quota remains.

At the owner's request on 2026-11-10, SillyTavern does **not** include Rewind:
there is no connection preset, discovery omits `rewind/` IDs, and hand-entered
Rewind generation is rejected. Existing explicit Rewind configurations in
other clients are retained; this is not a fleet-wide removal or a declaration
of unconditional availability.

The native Responses protocol, persistent device identity and quota behavior
below are technical requirements, not substitutes for the provider's usage
conditions.

## Models and clients

The authenticated upstream `/v1/models` list was checked on 2026-11-02. The
plugin registers and accepts these eight aliases from one shared allowlist:

- `rewind/gpt-5.6-luna`
- `rewind/gpt-5.6-sol`
- `rewind/gpt-5.6-terra`
- `rewind/gpt-6-astra`
- `rewind/gpt-6-luna`
- `rewind/gpt-6-sol`
- `rewind/gpt-6.1-sol`
- `rewind/gpt-chat-latest`

The executor strips only the `rewind/` prefix and forwards the selected alias
unchanged. Unknown IDs remain rejected. Model discovery is a checked-in
snapshot, not a startup network request; a listed model has not necessarily
been tested for generation.

The upstream list reports IDs and ownership, not limits or reasoning levels.
The plugin retains Astra's existing metadata (1,050,000 context, 96,000 output,
`low` through `xhigh`) and does not guess metadata for the new aliases.

Hank's Pi and OpenCode consume `lib/cliproxy-models.nix`. The named GPT aliases
use the existing same-name GPT client settings, with Rewind's 96,000 output
budget. Pi estimates their costs from the same-name public GPT price, not a
confirmed Rewind bill. `gpt-chat-latest` has no pinned underlying model: clients
use a conservative 128,000 context / 16,384 output budget, text input, and no
reasoning controls. Its Pi name marks the cost as unestimated; zero cost
fields mean no estimate, **not** a promise that the service is free.

The server plugin and client settings have separate activation paths. Deploy
gizmo's system through its configured builder to load the plugin; activate
Hank's Home Manager configuration on each client to update Pi and OpenCode.
Neither activation is performed merely by editing these files.

## Configuration and state

The service's generated YAML enables `plugins` and sets `plugins.dir` to the
plugin package's `lib` directory. Do not add an OpenAI-compatible or Codex
API-key entry for the Rewind provider: that would select a native executor
instead of this plugin.

The `cliproxy.service` pre-start step installs a credential descriptor at
`/var/lib/cli-proxy-api/auths/rewind.json`. It contains paths, not a provider
key. The raw key is encrypted under `rewind/api_key` in
`secrets/hosts/gizmo.yaml`, installed at `/run/secrets/rewind/api_key` for the
`cliproxy` user. Key changes restart the service.

The device's P-256 private key is created once at
`/var/lib/cli-proxy-api/rewind/device.json` with mode 0600. Preserve it across
restarts; a new device may require administrator approval. The short-lived
model session stays in memory. Concurrent requests share one renewal, and
each request receives its own ES256 DPoP proof bound to its URL, token,
nonce, method, and exact serialized body.

Only `cliproxy.service` runs. With the current script-based SOPS activation,
secrets are installed before systemd starts the service. If SOPS systemd
activation is enabled later, the module adds `Wants` and `After` for
`sops-install-secrets.service`. Plugin loading does not contact Rewind; an
authentication outage affects Rewind calls rather than delaying startup of
the other model providers.

## Balance in Pi

Hank's Pi statusline shows remaining Rewind balance instead of estimated session
cost. Only `cliproxy` models with the `rewind/` prefix query it; other models,
unlimited balances, and failed queries omit the field. A confirmed zero remains
`bal $0.00`, not an omitted or fabricated value.

The plugin also listens on the tailnet-only `rewind-balance` placement (currently
gizmo:8318), in the same `cliproxy.service` process. `GET /rewind/balance` accepts
the existing **client** API key, never the management key. It permits no other
path, query string, request body, or upstream URL. The generated configuration
contains only credential file paths; the Rewind key and device private key stay
on gizmo.

Balance requests reuse the model executor's device session and renewal lock.
The upstream is `GET /api/v1/rewind/usage`, signed with the short-lived model
token and a GET-specific DPoP proof. This is not the website's ordinary
`/v1/usage` endpoint; the investigation is in
`docs/incidents.md#rewind-app-balance`.

The relay validates the upstream quota envelope, returns only schema, currency,
`available_usd`, `exhausted`, and `as_of`, and caches successful responses for
60 seconds. Pi refreshes while a Rewind model is selected and after tasks;
switching models or closing the session cancels the pending UI request. Neither
network failures nor historical usage are converted to a zero balance.

## Responses behavior

Use the existing CLIProxyAPI URL and client API key:

```sh
curl "$CLIPROXY_BASE_URL/responses" \
  -H "Authorization: Bearer $CLIPROXY_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"rewind/gpt-6-astra","input":"Reply with OK","stream":true}'
```

Set `CLIPROXY_BASE_URL` to the existing URL ending in `/v1`.

The plugin forwards Responses input items, tools, reasoning parameters and
response events without converting them through Chat Completions. It sets
the upstream model alias and `store:false`, and consumes upstream SSE for
both streaming and ordinary JSON responses. For JSON responses, it returns
the terminal `response` object, retaining output items and usage.

Multi-turn requests should include the relevant previous output items and
`function_call_output` items in `input`. Server-side continuation using
`previous_response_id` has not been validated with Rewind's `store:false`
policy. Compact, token counting, and arbitrary upstream HTTP endpoints are
not exposed by this plugin.

## Connection policy {#connection-policy}

The plugin follows the model connection policy inspected in the official
1.1.7 preview installer (2026-11-09). Its SHA-256 and investigation are recorded
in [the policy investigation](incidents.md#rewind-client-policy-1-1-7).

Model connections race IPv4 and IPv6 **through validated TLS handshakes**, not
just TCP connection establishment. Each family advances through its resolved
addresses independently; only the winner receives HTTP request bytes, and all
losing connections are closed. DNS, TCP and TLS share a ten-second deadline.
The model transport uses pooled HTTP/1.1, validates certificates and SNI, does
not follow redirects, and does not inherit environment proxies. Authentication
and balance continue using their bounded, non-redirecting session HTTP client.

Model silence is bounded to **95 minutes**, including the wait for response
headers. Each received chunk renews that idle deadline; it is not a total
request-duration limit. An active stream may run longer. Downstream
cancellation and plugin shutdown still close pending DNS/TCP/TLS connections
and active model responses.

CLIProxyAPI's request-scoped HTTP callbacks carry a **single-use loopback hop**
to this native transport. The listener binds a random port on `127.0.0.1`, is
created lazily, and exposes only `POST /v1/responses` without query parameters.
An unguessable request ID selects immutable, in-memory authorization headers
and an exact body hash; neither tokens nor caller-selected upstream URLs are
accepted from that HTTP hop. IDs are consumed once and removed on cancellation.
The upstream remains pinned to Rewind, and device keys remain in their existing
state file. This is not a new fleet-facing endpoint or firewall opening.

The original short-lived token and request-specific DPoP proof stay inside the
plugin rather than entering the callback's HTTP logger. A separate
`x-rewind-client-request-id` correlates the upstream request; it is not an
idempotency key. Token and proof echoes are redacted across response chunk
boundaries, without altering ordinary Responses events.

### Failure and replay safety

A failed connection before the request is written is a transient transport
failure. Once a model request has been written, a connection loss, silent
response timeout or truncated accepted stream is
`REWIND_REQUEST_OUTCOME_UNKNOWN`: execution may already have happened, so it
must not be automatically replayed. The C ABI projects it as CLIProxyAPI's
recognized `stream_truncated` marker with HTTP 503 and the original Rewind code
in the bounded message. This prevents credential rotation/replay and avoids
credential cooldown; simply setting `retryable:false` would not do so.
**CLIProxyAPI 8.0.63 or later is required**: 8.0.60 ignores this routing marker.
The Nix module rejects older host packages; do not load plugin 0.2.0 into an
older hand-started CLIProxyAPI instance.
A confirmed HTTP refusal takes precedence even if its error body is truncated.
The plugin does not automatically replay model POSTs on 401/403; a model HTTP
401 clears the cached device session for a later request.

HTTP and terminal SSE failures share bounded, code-only classification. Validated
`rewind.auth-diagnostic.v1` envelopes distinguish session expiry, inactive
binding, request arrival, device proof, proof replay and internal service
assertion errors. Upstream model authorization is distinguished from Rewind key
eligibility only with the service's exact fields and a canonical request UUID.
Unknown messages, unsafe request IDs and unvalidated diagnostic fields are not
forwarded. Quota/context/image/rate-limit errors remain distinct.

The official desktop's local grants, backup worker and default-model UI are
not gateway protocols and are not imported here. Existing model aliases and
client budgets are unchanged, as are the [usage conditions](#usage-conditions).
The desktop's anonymous upgrade-policy polling is also UI-specific; the gateway
continues respecting the model/session endpoint's HTTP 426 upgrade refusal.

The plugin negotiates the 1.1.7 client protocol. HTTP 426 means this
protocol version needs reviewing against a newer official client; the error
includes the current version and, when supplied, a validated minimum version.
The upstream URL and protocol version live in `session.go`. A successful
challenge/session exchange does not prove model compatibility: upstream can
apply its minimum version only at `/v1/responses`. See
[the minimum-version investigation](incidents.md#rewind-minimum-client-version).

The session protocol's `platform` field uses the desktop-compatible `darwin`
tag even when the gateway runs on Linux. It identifies protocol compatibility,
not the gateway's OS. See [the Linux authentication investigation](incidents.md#rewind-desktop-platform).

## Verification

Build the plugin through the host configuration:

```sh
nix build .#nixosConfigurations.gizmo.config.services.cliproxy.rewind.package
just check-sops gizmo
```

The package runs Go tests covering registration of all eight models, raw and
prefixed alias forwarding, invalid-model rejection, ES256 proof validation,
exact request-body binding, concurrent renewal, expiry, key rotation,
persistent device identity, pending device approval, error redaction,
fragmented Responses SSE, reasoning events, tool calls and truncated output.
They also cover simultaneous family TLS races, no HTTP bytes on losing sockets,
certificate/SNI validation, shared deadlines, pending-dial cancellation,
HTTP/1.1 pooling, redirect refusal, single-use loopback authorization, exact
body binding, downstream cancellation before headers, uncertain-delivery
classification, validated error diagnostics and cross-chunk credential
redaction. The Nix package runs `go test -race ./...`; use the same command from
the package directory for the concurrency check.

For end-to-end validation, use a temporary CLIProxyAPI instance with this
plugin and a Rewind credential descriptor. Check `/v1/models`, a streamed
Responses request, a JSON Responses tool call, and a follow-up request with
its tool result before activating the fleet service.
