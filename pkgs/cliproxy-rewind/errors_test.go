package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestUpstreamErrorClassificationAndSafeRequestID(t *testing.T) {
	id := "01234567-89ab-4cde-8123-456789abcdef"
	for _, test := range []struct {
		name, body, code string
		status, want     int
	}{
		{"quota alias", `{"error":{"code":"balance_insufficient","message":"secret"}}`, "insufficient_quota", 403, 402},
		{"context", `{"error":{"code":"context_window_overflow"}}`, "context_window_exceeded", 400, 400},
		{"images", `{"error":{"code":"input_image_limit_exceeded"}}`, "image_limit_exceeded", 400, 400},
		{"unknown outcome", `{"error":{"code":"request_outcome_unknown"}}`, "REWIND_REQUEST_OUTCOME_UNKNOWN", 500, 503},
		{"upstream authorization", `{"error":{"type":"authentication_error","code":"authentication_error","stage":"upstream_http","request_id":"` + id + `"}}`, "upstream_auth", 401, 401},
		{"upstream permission", `{"error":{"type":"permission_error","code":"permission_denied","stage":"upstream_http","request_id":"` + id + `"}}`, "upstream_permission", 403, 403},
		{"unvalidated upstream attribution", `{"error":{"type":"authentication_error","code":"authentication_error","stage":"upstream_http","request_id":"secret"}}`, "rewind_auth_denied", 401, 401},
		{"neutral authorization", `{"error":{"message":"API key is bad secret"}}`, "rewind_auth_denied", 401, 401},
		{"unavailable", `{"error":{"message":"secret"}}`, "rewind_upstream", 503, 503},
		{"invalid unknown status", `{}`, "rewind_upstream", 302, 502},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := upstreamProblem(test.status, http.Header{"X-Rewind-Request-Id": {id}}, []byte(test.body))
			if p.HTTPStatus != test.want || p.Code != test.code || p.RequestID != id || !strings.Contains(p.Message, id) || strings.Contains(p.Message, "secret") || strings.Contains(p.Message, "API key is bad") {
				t.Fatalf("unsafe or incorrect classification: %+v", p)
			}
		})
	}
	p := upstreamProblem(403, http.Header{"X-Rewind-Auth-Error": {"REWIND_EXCLUSIVE_KEY_REQUIRED"}}, nil)
	if p.Code != "REWIND_EXCLUSIVE_KEY_REQUIRED" || p.HTTPStatus != 403 {
		t.Fatal("provider usage eligibility was not preserved")
	}
	p = upstreamProblem(401, http.Header{"X-Rewind-Request-Id": {"secret\nheader"}}, []byte(`{"error":{"request_id":"secret"}}`))
	if p.RequestID != "" || strings.Contains(p.Message, "secret") {
		t.Fatal("unvalidated request ID reached the client")
	}
}

func TestSafeRequestParameterDiagnostics(t *testing.T) {
	inline := []byte(`{"type":"error","code":"invalid_request_error","param":"input[0].content","message":"private"}`)
	if p := eventProblem(inline); p.HTTPStatus != 400 || p.SourceCode != "invalid_request_error" || p.Param != "input[0].content" || strings.Contains(p.Message, "private") {
		t.Fatalf("inline SSE validation diagnostics were lost: %+v", p)
	}
	for _, param := range []string{"input", "input[50].content[0].image_url", "tools[3].parameters", "reasoning.effort", "max_output_tokens"} {
		raw, _ := json.Marshal(map[string]any{"error": map[string]any{"code": "unsupported_parameter", "param": param, "message": "private API key and conversation text"}})
		for _, p := range []*problem{upstreamProblem(422, nil, raw), eventProblem(raw)} {
			if p.Code != "invalid_request_error" || p.Param != param || p.SourceCode != "unsupported_parameter" || !strings.Contains(p.Message, param) || strings.Contains(p.Message, "private") || strings.Contains(p.Message, "conversation") {
				t.Fatalf("unsafe or missing request diagnostics: %+v", p)
			}
		}
		if p := eventProblem(raw); p.HTTPStatus != 400 {
			t.Fatal("declared invalid request was treated as a transient server failure")
		}
		if p := upstreamProblem(422, nil, raw); p.HTTPStatus != 422 {
			t.Fatal("HTTP 422 was not preserved")
		}
	}
	for _, param := range []string{"secret-value", "input[0].secret\nAuthorization", "../../secret", "input[1234567]", strings.Repeat("input.", 100), "sk_secret_api_key"} {
		raw, _ := json.Marshal(map[string]any{"error": map[string]any{"code": "invalid_request_error", "param": param, "message": "private"}})
		p := eventProblem(raw)
		if p.Param != "" || strings.Contains(p.Message, param) || strings.Contains(p.Message, "private") {
			t.Fatalf("unvalidated parameter path was forwarded: %+v", p)
		}
	}
	p := upstreamProblem(400, nil, []byte(`{"error":{"code":"secret_provider_value","param":"input","message":"private"}}`))
	if p.SourceCode != "" || strings.Contains(p.Message, "secret_provider_value") || strings.Contains(p.Message, "private") {
		t.Fatal("unvalidated source code or upstream message was forwarded")
	}
}

func TestValidatedServiceDiagnostics(t *testing.T) {
	for _, test := range []struct{ stage, reason, code string }{
		{"session_token", "jwt_expired", "REWIND_SESSION_TOKEN_EXPIRED"},
		{"session_token", "jwt_invalid", "REWIND_SESSION_TOKEN_INVALID"},
		{"session_binding", "binding_inactive", "REWIND_SESSION_BINDING_INACTIVE"},
		{"request_arrival", "arrival_invalid", "REWIND_REQUEST_ARRIVAL_INVALID"},
		{"device_proof", "proof_invalid", "REWIND_DEVICE_PROOF_INVALID"},
		{"proof_replay", "replay_rejected", "REWIND_PROOF_REPLAY_REJECTED"},
		{"key_authorization", "unknown", "REWIND_KEY_AUTHORIZATION_DENIED"},
	} {
		t.Run(test.code, func(t *testing.T) {
			wire := wireError{Code: "REWIND_AUTH_DENIED", Stage: test.stage, Reason: test.reason, Origin: "service", Schema: "rewind.auth-diagnostic.v1", HTTPStatus: 401, RequestID: "01234567-89ab-4cde-8123-456789abcdef", ServerTime: "2026-11-10T04:48:02.123Z"}
			raw, _ := json.Marshal(map[string]any{"error": wire})
			if p := upstreamProblem(401, nil, raw); p.Code != test.code {
				t.Fatalf("validated diagnostic was lost: %+v", p)
			}
			if p := eventProblem(raw); p.Code != test.code || p.HTTPStatus != 401 {
				t.Fatalf("SSE diagnostic was lost: %+v", p)
			}
			for _, mutate := range []func(*wireError){
				func(e *wireError) { e.Schema = "untrusted" },
				func(e *wireError) { e.Origin = "upstream" },
				func(e *wireError) { e.HTTPStatus = 403 },
				func(e *wireError) { e.RequestID = "secret" },
				func(e *wireError) { e.ServerTime = "2026-02-30T00:00:00Z" },
				func(e *wireError) { e.Reason = "secret" },
			} {
				bad := wire
				mutate(&bad)
				raw, _ := json.Marshal(map[string]any{"error": bad})
				if p := upstreamProblem(401, nil, raw); p.Code != "rewind_auth_denied" || strings.Contains(p.Message, "secret") {
					t.Fatalf("unvalidated service diagnostic trusted: %+v", p)
				}
			}
		})
	}
}

func TestSSEFailureHTTPStatusAndNoReplayMarker(t *testing.T) {
	for _, test := range []struct {
		code string
		want int
	}{
		{"authentication_error", 401}, {"permission_error", 403}, {"rate_limit_exceeded", 429},
		{"insufficient_quota", 402}, {"rewind_request_outcome_unknown", 503},
		{"invalid_request_error", 400}, {"invalid_request", 400}, {"unsupported_parameter", 400},
		{"invalid_value", 400}, {"invalid_type", 400}, {"missing_required_parameter", 400},
		{"request_too_large", 413}, {"too_many_images", 400}, {"context_length_exceeded", 400},
		{"secret-authentication_error", 502},
	} {
		raw := []byte(`{"error":{"code":"` + test.code + `","message":"private token"}}`)
		p := eventProblem(raw)
		if p.HTTPStatus != test.want || strings.Contains(p.Message, "private") {
			t.Fatalf("incorrect SSE failure: %+v", p)
		}
	}
	p := unknownModelOutcome()
	p.RequestID = "01234567-89ab-4cde-8123-456789abcdef"
	routed := routingProblem(p)
	if p.Code != "REWIND_REQUEST_OUTCOME_UNKNOWN" || routed.Code != "stream_truncated" || routed.HTTPStatus != 503 || routed.RequestID != p.RequestID || !strings.Contains(routed.Message, p.Code) {
		t.Fatal("RPC or streamed failure can replay an uncertain model request")
	}
	if routingProblem(nil) != nil || routingProblem(fail(402, "insufficient_quota", "quota")).Code != "insufficient_quota" {
		t.Fatal("ordinary failures gained a no-replay marker")
	}
}
