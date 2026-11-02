package main

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var expectedRewindModels = []string{
	"gpt-5.6-luna",
	"gpt-5.6-sol",
	"gpt-5.6-terra",
	"gpt-6-astra",
	"gpt-6-luna",
	"gpt-6-sol",
	"gpt-6.1-sol",
	"gpt-chat-latest",
}

func TestRewindModelRegistration(t *testing.T) {
	for _, method := range []string{"model.static", "model.for_auth"} {
		t.Run(method, func(t *testing.T) {
			result, e := dispatch(method, nil)
			if e != nil {
				t.Fatal(e)
			}
			raw, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			var registered struct {
				Provider string
				Models   []struct {
					ID, Object, OwnedBy, DisplayName   string
					ContextLength, MaxCompletionTokens int
					SupportedGenerationMethods         []string
					Thinking                           *struct{ Levels []string }
				}
			}
			if err := json.Unmarshal(raw, &registered); err != nil {
				t.Fatal(err)
			}
			if registered.Provider != "rewind" || registered.Models == nil {
				t.Fatal("invalid Rewind model response")
			}
			if method == "model.static" {
				if len(registered.Models) != 0 {
					t.Fatal("models were exposed without a Rewind credential")
				}
				return
			}
			if len(registered.Models) != len(expectedRewindModels) {
				t.Fatalf("registered %d models, want %d", len(registered.Models), len(expectedRewindModels))
			}
			for i, model := range registered.Models {
				if model.ID != expectedRewindModels[i] || model.Object != "model" || model.OwnedBy != "rewind" || model.DisplayName == "" {
					t.Fatalf("unexpected model registration: %+v", model)
				}
				if !reflect.DeepEqual(model.SupportedGenerationMethods, []string{"chat"}) {
					t.Fatalf("missing generation method for %s", model.ID)
				}
				if model.ID == "gpt-6-astra" {
					if model.ContextLength != 1050000 || model.MaxCompletionTokens != 96000 || model.Thinking == nil || !reflect.DeepEqual(model.Thinking.Levels, []string{"low", "medium", "high", "xhigh"}) {
						t.Fatal("Astra's existing metadata changed")
					}
				} else if model.ContextLength != 0 || model.MaxCompletionTokens != 0 || model.Thinking != nil {
					t.Fatalf("unverified model limits or thinking levels for %s", model.ID)
				}
			}
		})
	}
}

func TestPrepareExecutionForEveryRewindModel(t *testing.T) {
	dir := t.TempDir()
	wantCredential := credential{Type: "rewind", APIKeyFile: filepath.Join(dir, "key"), DeviceFile: filepath.Join(dir, "device.json"), Prefix: "rewind"}
	storage, err := json.Marshal(wantCredential)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"model":"not-allowed","input":[{"type":"reasoning","encrypted_content":"opaque"},{"type":"function_call_output","call_id":"call_1","output":"42"}],"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}],"reasoning":{"effort":"high"},"max_output_tokens":100,"store":true,"stream":false}`)
	for _, id := range expectedRewindModels {
		for _, prefix := range []string{"", "rewind/"} {
			for _, format := range []string{"responses", "openai-response"} {
				t.Run(prefix+id+"/"+format, func(t *testing.T) {
					c, data, e := prepareExecution(executorRequest{Model: prefix + id, SourceFormat: format, Payload: payload, StorageJSON: storage})
					if e != nil {
						t.Fatal(e)
					}
					if c != wantCredential {
						t.Fatal("credential descriptor changed")
					}
					var want, got map[string]any
					if err := json.Unmarshal(payload, &want); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(data, &got); err != nil {
						t.Fatal(err)
					}
					want["model"], want["store"], want["stream"] = id, false, true
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("Responses fields changed or wrong upstream alias: %s", data)
					}
				})
			}
		}
	}
}

func TestPrepareExecutionRejectsInvalidRequests(t *testing.T) {
	dir := t.TempDir()
	storage, err := json.Marshal(credential{Type: "rewind", APIKeyFile: filepath.Join(dir, "key"), DeviceFile: filepath.Join(dir, "device.json")})
	if err != nil {
		t.Fatal(err)
	}
	valid := executorRequest{Model: "rewind/gpt-6-astra", SourceFormat: "responses", Payload: []byte(`{"input":"hello"}`), StorageJSON: storage}
	for _, id := range []string{"", "gpt-6.1-terra", "rewind/unknown", "rewind/rewind/gpt-6-astra", "other/gpt-6-astra"} {
		t.Run("model/"+id, func(t *testing.T) {
			req := valid
			req.Model = id
			if _, _, e := prepareExecution(req); e == nil || e.HTTPStatus != 404 || e.Code != "model_not_found" {
				t.Fatalf("unsupported model accepted: %q, error: %v", id, e)
			}
		})
	}
	for _, tc := range []struct {
		name, code string
		status     int
		change     func(*executorRequest)
	}{
		{"format", "invalid_request", 400, func(req *executorRequest) { req.SourceFormat = "chat-completions" }},
		{"alternate endpoint", "not_supported", 400, func(req *executorRequest) { req.Alt = "compact" }},
		{"oversized payload", "invalid_request_error", 413, func(req *executorRequest) { req.Payload = make([]byte, (32<<20)+1) }},
		{"invalid credential", "rewind_credential", 400, func(req *executorRequest) { req.StorageJSON = []byte(`{"type":"codex"}`) }},
		{"invalid JSON", "invalid_request_error", 400, func(req *executorRequest) { req.Payload = []byte(`{`) }},
		{"null payload", "invalid_request_error", 400, func(req *executorRequest) { req.Payload = []byte(`null`) }},
		{"array payload", "invalid_request_error", 400, func(req *executorRequest) { req.Payload = []byte(`[]`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := valid
			tc.change(&req)
			if _, _, e := prepareExecution(req); e == nil || e.HTTPStatus != tc.status || e.Code != tc.code {
				t.Fatalf("expected %d %s, got %v", tc.status, tc.code, e)
			}
		})
	}
}

func TestResponsesEventsAndToolContinuation(t *testing.T) {
	final := `{"id":"resp_1","status":"completed","model":"gpt-6.1-sol-1","output":[{"type":"reasoning","encrypted_content":"opaque"},{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{\"x\":1}"}],"usage":{"input_tokens":10,"output_tokens":5}}`
	events := ": keepalive\n\nevent: response.reasoning_summary_text.delta\ndata: {\"type\":\"response.reasoning_summary_text.delta\",\"delta\":\"reason\"}\n\nevent: response.function_call_arguments.delta\ndata: {\"type\":\"response.function_call_arguments.delta\",\"delta\":\"{\\\"x\\\":1}\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":" + final + "}\n\n"
	var emitted bytes.Buffer
	response, e := readSSE(&oneByteReader{strings.NewReader(events)}, func(frame []byte) *problem { emitted.Write(frame); return nil })
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(response, []byte(final)) {
		t.Fatal("terminal Responses object was changed")
	}
	if emitted.String() != events {
		t.Fatal("Responses reasoning or tool events were changed")
	}
	var v map[string]any
	if json.Unmarshal(response, &v) != nil || v["usage"] == nil {
		t.Fatal("usage was lost")
	}
	if _, e := readSSE(strings.NewReader(events), nil); e != nil {
		t.Fatal(e)
	}
	if _, e := readSSE(strings.NewReader("data: {\"type\":\"response.created\"}\n\n"), nil); e == nil {
		t.Fatal("truncated stream reported success")
	}
	if _, e := readSSE(strings.NewReader("data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"message\":\"secret\"}}}\n\n"), nil); e == nil || strings.Contains(e.Message, "secret") {
		t.Fatal("failed stream was not sanitized")
	}
	if _, e := readSSE(strings.NewReader("data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"insufficient_quota\"}}}\n\n"), nil); e == nil || e.HTTPStatus != 402 {
		t.Fatal("streaming quota error lost its HTTP status")
	}
}

type oneByteReader struct{ io.Reader }

func (r *oneByteReader) Read(out []byte) (int, error) { return r.Reader.Read(out[:1]) }

func TestPluginDeclaresResponsesAndDoesNotConnectAtStartup(t *testing.T) {
	registered, e := dispatch("plugin.register", nil)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(registered)
	if !bytes.Contains(raw, []byte(`"executor_input_formats":["responses"]`)) || !bytes.Contains(raw, []byte(`"executor_output_formats":["responses"]`)) {
		t.Fatal("plugin did not declare native Responses")
	}
	if !bytes.Contains(raw, []byte(`"GitHubRepository":"https://github.com/imdomestic/nix-config"`)) {
		t.Fatal("required plugin metadata is missing")
	}
	if _, e := dispatch("auth.parse", []byte(`{"RawJSON":"eyJ0eXBlIjoiY29kZXgifQ=="}`)); e != nil {
		t.Fatal("plugin interfered with another provider")
	}
}
