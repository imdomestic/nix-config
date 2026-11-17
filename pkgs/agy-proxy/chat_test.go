package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestChatCompatibilityIsOptInAndAuthenticated(t *testing.T) {
	var calls atomic.Int32
	p := testProxy(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) }, fixedCredentials{credential{AccessToken: "google", Project: "p"}})
	if request(p, "POST", "/v1/chat/completions", `{}`).Code != 404 {
		t.Fatal("Chat was enabled by default")
	}
	p.openaiCompat = true
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"POST", "/v1/chat/completions", `{}`, 400}, {"POST", "/v1/completions", `{}`, 404},
		{"POST", "/v1/chat/completions?key=private", `{}`, 400}, {"GET", "/v1/models?limit=1", "", 400},
		{"POST", "/v1/chat/completions", `{"model":"gpt-not-supported","messages":[]}`, 400},
	} {
		w := request(p, tc.method, tc.path, tc.body)
		if w.Code != tc.status {
			t.Errorf("route %s got %d want %d", tc.path, w.Code, tc.status)
		}
	}
	r := httptest.NewRequest("GET", "/v1/models", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 401 || !strings.Contains(w.Body.String(), "authentication_error") {
		t.Fatal("Chat key authentication failed")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid requests reached upstream")
	}
}

func TestChatGenerationUsesOriginalSystemAndNativeEnvelope(t *testing.T) {
	var calls atomic.Int32
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1internal:generateContent" || r.Header.Get("Authorization") != "Bearer google-private" {
			t.Fatal("wrong upstream route or key")
		}
		var envelope struct {
			Model   string
			Project string
			Request struct {
				SessionID string                                  `json:"sessionId"`
				System    struct{ Parts []struct{ Text string } } `json:"systemInstruction"`
				Config    struct {
					Max int `json:"maxOutputTokens"`
				} `json:"generationConfig"`
			}
		}
		_ = json.NewDecoder(r.Body).Decode(&envelope)
		if envelope.Model != "gemini-test" || envelope.Project != "private-project" || envelope.Request.SessionID != "client-session" || envelope.Request.System.Parts[0].Text != "Keep my Pi identity." || envelope.Request.Config.Max != 8192 {
			t.Error("request rewritten beyond format conversion")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"response":{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"OK"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":2,"thoughtsTokenCount":3,"cachedContentTokenCount":4,"totalTokenCount":15}}}`)
	}, fixedCredentials{credential{AccessToken: "google-private", Project: "private-project"}})
	p.openaiCompat = true
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"gemini-test","messages":[{"role":"system","content":"Keep my Pi identity."},{"role":"user","content":"hi"}],"max_tokens":8192}`))
	r.Header.Set("Authorization", "Bearer "+testKey)
	r.Header.Set("X-Session-Id", "client-session")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 200 || calls.Load() != 1 {
		t.Fatalf("unexpected Chat status %d", w.Code)
	}
	var out struct {
		Object  string
		Choices []struct {
			Message struct{ Content string }
			Finish  string `json:"finish_reason"`
		}
		Usage struct {
			Completion int `json:"completion_tokens"`
		}
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Object != "chat.completion" || out.Choices[0].Message.Content != "OK" || out.Choices[0].Finish != "stop" || out.Usage.Completion != 5 {
		t.Fatalf("bad Chat response: %s", w.Body.String())
	}
}

func TestChatUpstreamErrorsAreNotRetried(t *testing.T) {
	var calls atomic.Int32
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "23")
		w.Header().Set("Location", "https://evil.invalid/private")
		w.WriteHeader(429)
		_, _ = io.WriteString(w, `{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"reason":"original"}]}}`)
	}, fixedCredentials{credential{AccessToken: "google", Project: "p"}})
	p.openaiCompat = true
	w := request(p, "POST", "/v1/chat/completions", `{"model":"gemini-test","messages":[{"role":"user","content":"hi"}],"stream":true}`)
	if w.Code != 429 || calls.Load() != 1 || w.Header().Get("Retry-After") != "23" || !strings.Contains(w.Body.String(), "RESOURCE_EXHAUSTED") || w.Header().Get("Location") != "" {
		t.Fatal("upstream error was hidden, retried or leaked redirect")
	}
}

func TestChatModelDiscoveryAndLimits(t *testing.T) {
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1internal:fetchAvailableModels" {
			t.Fatal("unexpected request")
		}
		_, _ = io.WriteString(w, `{"models":{"gemini-new":{"displayName":"New Gemini","maxTokens":1048576,"maxOutputTokens":262144},"claude-ignore":{}}}`)
	}, fixedCredentials{credential{AccessToken: "google", Project: "p"}})
	p.openaiCompat = true
	w := request(p, "GET", "/v1/models", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"gemini-new"`) || !strings.Contains(w.Body.String(), `"object":"list"`) || strings.Contains(w.Body.String(), "claude-ignore") {
		t.Fatalf("bad model list %s", w.Body.String())
	}
	w = request(p, "GET", "/v1/models/gemini-new", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"max_output_tokens":262144`) {
		t.Fatal("actual model limits missing")
	}
	if request(p, "GET", "/v1/models/gemini-unavailable", "").Code != 404 {
		t.Fatal("invented model")
	}
}

func TestChatStreamCancelsAndTruncationIsNotSuccess(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "truncated"}[truncated], func(t *testing.T) {
			canceled := make(chan struct{})
			p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: {\"response\":{\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"partial\"}]}}]}}\n\n")
				w.(http.Flusher).Flush()
				if !truncated {
					<-r.Context().Done()
					close(canceled)
				}
			}, fixedCredentials{credential{AccessToken: "google", Project: "p"}})
			p.openaiCompat = true
			server := httptest.NewServer(p)
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/v1/chat/completions", strings.NewReader(`{"model":"gemini-test","messages":[{"role":"user","content":"hi"}],"stream":true}`))
			r.Header.Set("Authorization", "Bearer "+testKey)
			response, err := server.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if truncated {
				data, err := io.ReadAll(response.Body)
				if err == nil || strings.Contains(string(data), "[DONE]") || strings.Contains(string(data), `"finish_reason":"stop"`) {
					t.Fatal("truncated stream became success")
				}
			} else {
				buffer := make([]byte, 1)
				_, _ = response.Body.Read(buffer)
				cancel()
				select {
				case <-canceled:
				case <-time.After(3 * time.Second):
					t.Fatal("client cancel did not propagate")
				}
			}
		})
	}
}
