package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCountTokensContentsOnlyContract(t *testing.T) {
	for _, input := range []string{`{"contents":[{"role":"user","parts":[{"text":"hello world"}]}]}`, `{"generateContentRequest":{"model":"models/gemini-test","contents":[{"role":"user","parts":[{"text":"hello world"}]}]}}`} {
		body, err := countTokensEnvelope([]byte(input), "gemini-test")
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Request struct {
				Model    string
				Contents []json.RawMessage
			}
		}
		if json.Unmarshal(body, &envelope) != nil || envelope.Request.Model != "models/gemini-test" || len(envelope.Request.Contents) != 1 {
			t.Fatal("invalid real CCPA count envelope")
		}
		if strings.Contains(string(body), "project") || strings.Contains(string(body), "sessionId") {
			t.Fatal("generation metadata leaked into count endpoint")
		}
	}
	for _, input := range []string{`null`, `[]`, `{"contents":[]}`, `{"contents":[{"parts":[]}]}`, `{"model":"gemini-other","contents":[{"parts":[{"text":"hi"}]}]}`, `{"contents":[{"parts":[{}]}]}`, `{"contents":[{"parts":[{"text":"hi"}]}],"systemInstruction":{"parts":[{"text":"not counted"}]}}`, `{"generateContentRequest":{"contents":[{"parts":[{"text":"hi"}]}],"tools":[]}}`, `{"generateContentRequest":{"contents":[{"parts":[{"text":"hi"}]}]},"contents":[]}`} {
		if _, err := countTokensEnvelope([]byte(input), "gemini-test"); err == nil {
			t.Errorf("unsupported/ambiguous count accepted: %s", input)
		}
	}
}

func TestCountTokensRealRouteAndValidationBeforeAuthSource(t *testing.T) {
	var calls atomic.Int32
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1internal:countTokens" || r.Header.Get("Authorization") != "Bearer google-private" {
			t.Error("wrong count route or credential")
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"model":"models/gemini-test"`) {
			t.Error("model not nested in count request")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"totalTokens":2,"futureCountField":1}`)
	}, fixedCredentials{credential{AccessToken: "google-private"}})
	w := request(p, "POST", "/v1beta/models/gemini-test:countTokens", `{"contents":[{"role":"user","parts":[{"text":"hello world"}]}]}`)
	if w.Code != 200 || w.Header().Get("X-Agy-Count-Scope") != "contents-only" || !strings.Contains(w.Body.String(), `"totalTokens":2`) || !strings.Contains(w.Body.String(), "futureCountField") || calls.Load() != 1 {
		t.Fatal("count response or scope incorrect")
	}
	p.source = sourceFunc(func(context.Context) (credential, error) {
		t.Fatal("invalid request accessed credentials")
		return credential{}, errCredentials
	})
	if request(p, "POST", "/v1beta/models/gemini-test:countTokens", `{"contents":[],"tools":[]}`).Code != 400 {
		t.Fatal("ignored count fields were accepted")
	}
}

func TestCountTokensErrorAndNoFakeZero(t *testing.T) {
	for _, body := range []string{`{}`, `{"error":{"code":429}}`, `{"totalTokens":-1}`, `{"totalTokens":"2"}`, `null`, `{"totalTokens":null}`, `{"totalTokens":2,"error":{"code":429}}`} {
		p := testProxy(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }, fixedCredentials{credential{AccessToken: "google"}})
		w := request(p, "POST", "/v1beta/models/gemini-test:countTokens", `{"contents":[{"parts":[{"text":"hi"}]}]}`)
		if w.Code != 502 {
			t.Errorf("invalid counter became success: %s", body)
		}
	}
	var calls atomic.Int32
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "10")
		w.WriteHeader(429)
		_, _ = io.WriteString(w, `{"error":{"status":"RESOURCE_EXHAUSTED"}}`)
	}, fixedCredentials{credential{AccessToken: "google"}})
	w := request(p, "POST", "/v1beta/models/gemini-test:countTokens", `{"contents":[{"parts":[{"text":"hi"}]}]}`)
	if w.Code != 429 || calls.Load() != 1 || w.Header().Get("Retry-After") != "10" {
		t.Fatal("counter retry/error semantics changed")
	}
}

func TestImageGenerationEnvelopeLane(t *testing.T) {
	for _, tc := range []struct{ model, body, want string }{
		{"gemini-3.1-flash-image", `{"contents":[]}`, "image_gen"},
		{"gemini-test", `{"generationConfig":{"responseModalities":["TEXT","IMAGE"]}}`, "image_gen"},
		{"gemini-test", `{"generationConfig":{"responseModalities":["TEXT"]}}`, "agent"},
	} {
		body, err := buildEnvelope([]byte(tc.body), tc.model, "p", "session", "request")
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			Type string `json:"requestType"`
		}
		_ = json.Unmarshal(body, &result)
		if result.Type != tc.want {
			t.Errorf("%s used wrong request lane: %s", tc.model, result.Type)
		}
	}
}

func TestCapabilitiesAndUnsupportedAreHonestAndAuthenticated(t *testing.T) {
	p := testProxy(t, func(http.ResponseWriter, *http.Request) { t.Fatal("capability/unsupported route contacted Google") }, sourceFunc(func(context.Context) (credential, error) {
		t.Fatal("capability route read Google credentials")
		return credential{}, errCredentials
	}))
	p.openaiCompat = true
	w := request(p, "GET", "/v1beta/capabilities", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "contents-only") || !strings.Contains(w.Body.String(), "gateway implementation features") {
		t.Fatal("bad custom capability document")
	}
	for _, path := range []string{"/v1/files", "/v1/files/anything", "/v1/batches", "/v1/embeddings", "/v1/audio/speech", "/v1/videos", "/v1/realtime", "/v1beta/files", "/v1beta/cachedContents", "/v1beta/batches", "/v1beta/models/gemini-test:embedContent"} {
		w := request(p, "POST", path, `{}`)
		if w.Code != 501 {
			t.Errorf("unbacked API %s got %d not explicit 501", path, w.Code)
		}
	}
}
