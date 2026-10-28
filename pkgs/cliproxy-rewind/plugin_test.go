package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

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
