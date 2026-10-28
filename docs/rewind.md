# Rewind provider for CLIProxyAPI

`pkgs/cliproxy-rewind/` builds a C ABI shared library for CLIProxyAPI 8. The
plugin owns Rewind authentication and declares native Responses input and
output. CLIProxyAPI still owns client authentication, credential selection,
protocol translation for other client formats, and usage collection.

The fleet enables it on tank through `services.cliproxy.rewind`. Its model is
`rewind/gpt-6-astra`, kept separate from the existing unprefixed Codex models.
The upstream controls what this alias resolves to; the plugin preserves the
upstream response's `model` field.

## Configuration and state

The service's generated YAML enables `plugins` and sets `plugins.dir` to the
plugin package's `lib` directory. Do not add an OpenAI-compatible or Codex
API-key entry for the Rewind provider: that would select a native executor
instead of this plugin.

The `cliproxy.service` pre-start step installs a credential descriptor at
`/var/lib/cli-proxy-api/auths/rewind.json`. It contains paths, not a provider
key. The raw key is encrypted under `rewind/api_key` in
`secrets/hosts/tank.yaml`, installed at `/run/secrets/rewind/api_key` for the
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

Model HTTP requests use CLIProxyAPI's request-scoped HTTP callbacks, so
downstream cancellation also closes the upstream request. Connection setup
is bounded to 45 seconds; active streams may continue as long as their
upstream remains active, with a five-minute idle timeout. Truncated streams
are failures. Authentication, quota and HTTP errors have bounded, sanitized
messages rather than forwarding arbitrary upstream error text.

Rewind currently negotiates the 1.0.6 client protocol. HTTP 426 means this
protocol version needs reviewing against a newer official client. The
upstream URL and protocol version live in `session.go`.

The session protocol's `platform` field uses the desktop-compatible `darwin`
tag even when the gateway runs on Linux. It identifies protocol compatibility,
not the gateway's OS. See [the Linux authentication investigation](incidents.md#rewind-desktop-platform).

## Verification

Build the plugin through the host configuration:

```sh
nix build .#nixosConfigurations.tank.config.services.cliproxy.rewind.package
just check-sops tank
```

The package runs Go tests covering ES256 proof validation, exact request-body
binding, concurrent renewal, expiry, key rotation, persistent device identity,
pending device approval, error redaction, fragmented Responses SSE, reasoning
events, tool calls and truncated output. Run `go test -race ./...` from the
package directory for the concurrency check.

For end-to-end validation, use a temporary CLIProxyAPI instance with this
plugin and a Rewind credential descriptor. Check `/v1/models`, a streamed
Responses request, a JSON Responses tool call, and a follow-up request with
its tool result before activating the fleet service.
