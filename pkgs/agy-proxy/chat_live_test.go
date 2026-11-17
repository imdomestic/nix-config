package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// Explicit opt-in: exercise this adapter through an already deployed Gemini API,
// without exporting its Google OAuth credentials or changing the live gateway.
// AGY_CHAT_LIVE_URL must end in /agy/v1beta; AGY_CHAT_LIVE_KEY_FILE is a private proxy key.
func TestChatLiveThroughGemini(t *testing.T) {
	base, keyFile := os.Getenv("AGY_CHAT_LIVE_URL"), os.Getenv("AGY_CHAT_LIVE_KEY_FILE")
	if base == "" || keyFile == "" {
		t.Skip("live Gemini verification is opt-in")
	}
	origin, err := url.Parse(base)
	if err != nil || origin.Scheme != "https" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" {
		t.Fatal("live URL must be a trusted HTTPS Gemini base URL")
	}
	key, err := readRuntimeSecret(keyFile, 4096)
	if err != nil {
		t.Fatal("cannot read private proxy key")
	}
	p := newProxy(origin, chatLiveTransport{base: strings.TrimRight(base, "/"), key: strings.TrimSpace(string(key))}, fixedCredentials{credential{AccessToken: "local-test-placeholder-never-forwarded", Project: "local-test-placeholder"}}, testKey, defaultUserAgent, 64<<20)
	p.openaiCompat = true
	call := func(body map[string]any) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(chatRaw(body)))
		r.Header.Set("Authorization", "Bearer "+testKey)
		r.Header.Set("X-Agy-Session-Id", "agy-chat-live-verification")
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("live Chat request failed: HTTP %d (body withheld)", w.Code)
		}
		return w
	}
	body := map[string]any{"model": "gemini-4-hydrogen-high", "messages": []any{map[string]any{"role": "user", "content": "Reply exactly AGY_CHAT_JSON_OK. Do not use tools."}}, "max_tokens": 8192, "reasoning_effort": "high"}
	w := call(body)
	var first struct {
		Choices []struct{ Message map[string]any }
	}
	if json.Unmarshal(w.Body.Bytes(), &first) != nil || len(first.Choices) != 1 || !strings.Contains(first.Choices[0].Message["content"].(string), "AGY_CHAT_JSON_OK") {
		t.Fatal("live Chat text marker missing")
	}
	t.Log("real Chat JSON translation returned the requested marker")
	body["stream"] = true
	body["stream_options"] = map[string]bool{"include_usage": true}
	body["messages"] = []any{map[string]any{"role": "user", "content": "Reply exactly AGY_CHAT_STREAM_OK. Do not use tools."}}
	w = call(body)
	var text strings.Builder
	usage := false
	for _, line := range strings.Split(w.Body.String(), "\n") {
		if !strings.HasPrefix(line, "data: ") || line == "data: [DONE]" {
			continue
		}
		var event struct {
			Error   json.RawMessage
			Choices []struct{ Delta struct{ Content string } }
			Usage   json.RawMessage
		}
		if json.Unmarshal([]byte(line[6:]), &event) != nil || len(event.Error) > 0 {
			t.Fatal("live Chat stream error")
		}
		for _, choice := range event.Choices {
			text.WriteString(choice.Delta.Content)
		}
		usage = usage || len(event.Usage) > 0
	}
	if !strings.Contains(text.String(), "AGY_CHAT_STREAM_OK") || !strings.HasSuffix(w.Body.String(), "data: [DONE]\n\n") || !usage {
		t.Fatal("live Chat streaming output, usage or terminal marker missing")
	}
	t.Log("real Chat SSE translation returned text, usage and validated DONE")
	delete(body, "stream")
	delete(body, "stream_options")
	body["messages"] = []any{map[string]any{"role": "user", "content": "Call proxy_probe with value ok. After its result reply exactly AGY_CHAT_TOOL_OK."}}
	body["tools"] = []any{map[string]any{"type": "function", "function": map[string]any{"name": "proxy_probe", "description": "A verification stub returning a fixed result", "parameters": map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "string", "enum": []string{"ok"}}}, "required": []string{"value"}}}}}
	body["stream"] = true
	w = call(body)
	message, _ := chatAssembleStream(t, w.Body.String())
	delete(body, "stream")
	var response struct {
		Choices []struct{ Message map[string]any }
	}
	calls, ok := message["tool_calls"].([]any)
	if !ok || len(calls) != 1 || !strings.Contains(string(chatRaw(message["extra_content"])), "thoughtSignature") {
		t.Fatal("native tool call or signature carrier missing")
	}
	tool := calls[0].(map[string]any)
	if tool["function"].(map[string]any)["name"] != "proxy_probe" {
		t.Fatal("unexpected live tool name")
	}
	body["messages"] = append(body["messages"].([]any), message, map[string]any{"role": "tool", "tool_call_id": tool["id"], "content": "ok"})
	w = call(body)
	if json.Unmarshal(w.Body.Bytes(), &response) != nil || !strings.Contains(response.Choices[0].Message["content"].(string), "AGY_CHAT_TOOL_OK") {
		t.Fatal("live Chat native-signature replay failed")
	}
	t.Log("real two-turn Chat tool call replayed its native signature and returned the requested marker")
}

type chatLiveTransport struct{ base, key string }

func (t chatLiveTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var envelope struct {
		Model   string
		Request json.RawMessage
	}
	if json.NewDecoder(r.Body).Decode(&envelope) != nil {
		return nil, io.ErrUnexpectedEOF
	}
	action := strings.TrimPrefix(r.URL.Path, "/v1internal:")
	if action != "generateContent" && action != "streamGenerateContent" {
		return nil, io.ErrUnexpectedEOF
	}
	raw := t.base + "/models/" + envelope.Model + ":" + action
	if action == "streamGenerateContent" {
		raw += "?alt=sse"
	}
	sending, err := http.NewRequestWithContext(r.Context(), "POST", raw, bytes.NewReader(envelope.Request))
	if err != nil {
		return nil, err
	}
	sending.GetBody = nil
	sending.Header.Set("Content-Type", "application/json")
	sending.Header.Set("X-Goog-Api-Key", t.key)
	return (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(sending)
}
