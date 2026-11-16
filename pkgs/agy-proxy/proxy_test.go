package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testKey = "local-proxy-key-not-google-token"

type fixedCredentials struct{ c credential }

func (s fixedCredentials) Load(context.Context) (credential, error) { return s.c, nil }

func testProxy(t *testing.T, handler http.HandlerFunc, source credentialSource) *proxy {
	t.Helper()
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	origin, _ := url.Parse(upstream.URL)
	return newProxy(origin, upstream.Client().Transport, source, testKey, defaultUserAgent, 1<<20)
}

func request(p *proxy, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+testKey)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

func TestNativeOpaqueChunkedForwarding(t *testing.T) {
	body := " {\"request\":{\"contents\":[{\"role\":\"model\",\"parts\":[{\"thoughtSignature\":\"not-a-bypass\",\"functionCall\":{\"name\":\"untouched.name\",\"args\":{\"x\":1}}}]}],\"generationConfig\":{\"maxOutputTokens\":262144}},\"requestId\":\"exact-original\"} "
	sse := ": native comment\r\nid: 42\r\nevent: message\r\ndata: {\"response\":{\"candidates\":[]},\"traceId\":\"trace\",\"metadata\":{\"unknown\":1}}\r\n\r\n"
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		if string(got) != body || r.Header.Get("Authorization") != "Bearer google-private" || r.Header.Get("User-Agent") != "original-cli" {
			t.Error("native request was mutated")
		}
		if r.URL.RequestURI() != "/v1internal:streamGenerateContent?alt=sse" {
			t.Errorf("wrong URL: %s", r.URL)
		}
		for _, key := range []string{"X-Agy-Proxy-Key", "X-Forwarded-For", "Forwarded", "Idempotency-Key"} {
			if r.Header.Get(key) != "" {
				t.Errorf("private/replay header leaked: %s", key)
			}
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, sse)
	}, nil)
	r := httptest.NewRequest("POST", "/v1internal:streamGenerateContent?alt=sse", io.NopCloser(strings.NewReader(body)))
	r.ContentLength = -1
	r.TransferEncoding = []string{"chunked"}
	r.Header.Set("Authorization", "Bearer google-private")
	r.Header.Set("X-Agy-Proxy-Key", testKey)
	r.Header.Set("User-Agent", "original-cli")
	r.Header.Set("X-Forwarded-For", "private-client")
	r.Header.Set("Forwarded", "private-client")
	r.Header.Set("Idempotency-Key", "do-not-replay")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != sse {
		t.Fatalf("native stream was changed: status %d body %q", w.Code, w.Body.String())
	}
}

func TestRoutesAndAuthentication(t *testing.T) {
	var calls atomic.Int32
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }, fixedCredentials{})
	for _, tc := range []struct {
		method, path string
		code         int
	}{
		{"GET", "/healthz", 200}, {"POST", "/v1internal:deleteUser", 404},
		{"GET", "/v1internal:generateContent", 404}, {"POST", "/v1/chat/completions", 404},
		{"POST", "/v1beta/modelsXYZ", 404}, {"POST", "/v1beta/models/claude-opus:generateContent", 400},
		{"POST", "/v1beta/models/gemini-test:generateContent?key=private", 400},
		{"GET", "/v1beta/models?pageSize=1", 400}, {"POST", "/v1internal:generateContent?key=private", 401},
	} {
		w := request(p, tc.method, tc.path, `{}`)
		if w.Code != tc.code {
			t.Errorf("%s %s got %d want %d", tc.method, tc.path, w.Code, tc.code)
		}
	}
	for _, path := range []string{"/v1beta/models", "/v1internal:generateContent"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer google-token")
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Errorf("unauthorized route accepted: %s", path)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid requests reached upstream")
	}
}

func TestGoogleSDKKeyHeader(t *testing.T) {
	p := testProxy(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid JSON reached upstream") }, fixedCredentials{})
	for _, conflict := range []bool{false, true} {
		r := httptest.NewRequest("POST", "/v1beta/models/gemini-test:generateContent", strings.NewReader("null"))
		r.Header.Set("X-Goog-Api-Key", testKey)
		want := 400
		if conflict {
			r.Header.Set("Authorization", "Bearer different-key")
			want = 401
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("Google SDK key auth got %d want %d", w.Code, want)
		}
	}
}

func TestEnvelopePreservesGeminiSemantics(t *testing.T) {
	body := `{"contents":[{"role":"user","parts":[{"text":"before"},{"functionResponse":{"name":"native_tool","response":{"enum":[1,2]}},"thoughtSignature":"original"},{"text":"after"}]},{"role":"model","parts":[{"thought":true,"text":"thinking","thoughtSignature":"sig"}]}],"tools":[{"functionDeclarations":[{"name":"tool.with.dots","parameters":{"type":"OBJECT","properties":{"x":{"enum":["a","b"],"oneOf":[{},{}],"$ref":"#/defs/X"}}}}]}],"generationConfig":{"maxOutputTokens":262144,"thinkingConfig":{"thinkingLevel":"HIGH","includeThoughts":true}},"safetySettings":[{"category":"native","threshold":"OFF"}],"labels":{"original":"yes"},"unknown":{"keep":true},"sessionId":"explicit-native"}`
	encoded, err := buildEnvelope([]byte(body), "gemini-test", "project", "ignored-header", "original-request")
	if err != nil {
		t.Fatal(err)
	}
	var outer map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &outer)
	var before, after any
	_ = json.Unmarshal([]byte(body), &before)
	_ = json.Unmarshal(outer["request"], &after)
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	if !bytes.Equal(a, b) {
		t.Fatalf("inner request changed\nbefore: %s\nafter: %s", b, a)
	}
	if string(outer["requestId"]) != `"original-request"` || string(outer["model"]) != `"gemini-test"` {
		t.Fatal("outer fields changed")
	}
	for _, invalid := range []string{"null", "[]", "bad", `{"x":`} {
		if _, err := buildEnvelope([]byte(invalid), "gemini-test", "project", "", ""); err == nil {
			t.Errorf("accepted %q", invalid)
		}
	}
	for _, input := range []string{`{}`, " { \n\"contents\": []\n } "} {
		got, err := buildEnvelope([]byte(input), "gemini-test", "project", "stable-session", "")
		if err != nil {
			t.Fatal(err)
		}
		var x struct {
			Request struct {
				Session string `json:"sessionId"`
			}
			ID string `json:"requestId"`
		}
		_ = json.Unmarshal(got, &x)
		if x.Request.Session != "stable-session" || !strings.HasPrefix(x.ID, "agent/") || strings.Count(x.ID, "/") != 4 {
			t.Fatal("invalid native ID format")
		}
	}
	one, _ := buildEnvelope([]byte(`{}`), "gemini-test", "p", "", "")
	two, _ := buildEnvelope([]byte(`{}`), "gemini-test", "p", "", "")
	if bytes.Equal(one, two) {
		t.Fatal("independent requests got identical IDs")
	}
}

func TestGeminiGenerationAndUpstreamErrors(t *testing.T) {
	for _, status := range []int{200, 403, 429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			response := `{"response":{"candidates":[{"index":0,"content":{"parts":[{"text":"OK","thoughtSignature":"sig"}]}},{"index":1,"finishReason":"MAX_TOKENS"}],"unknown":{"original":true}},"metadata":{"outer":true}}`
			p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer google-private" || r.Header.Get("User-Agent") != defaultUserAgent {
					t.Error("wrong upstream credentials or UA")
				}
				if r.URL.Path != "/v1internal:generateContent" {
					t.Error("wrong generation endpoint")
				}
				w.Header().Set("Retry-After", "17")
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Location", "https://evil.invalid/?secret=private")
				w.Header().Set("Set-Cookie", "secret=private")
				w.WriteHeader(status)
				if status == 200 {
					_, _ = io.WriteString(w, response)
				} else {
					_, _ = io.WriteString(w, `{"error":{"status":"RESOURCE_EXHAUSTED","unknown":"preserve"}}`)
				}
			}, fixedCredentials{credential{AccessToken: "google-private", Project: "existing-project"}})
			w := request(p, "POST", "/v1beta/models/gemini-test:generateContent", `{"contents":[]}`)
			if w.Code != status || calls.Load() != 1 || w.Header().Get("Retry-After") != "17" {
				t.Fatalf("status/retry changed: %d calls %d", w.Code, calls.Load())
			}
			if w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("private response headers exposed")
			}
			if status == 200 {
				want, _ := unwrapResponse([]byte(response))
				if !bytes.Equal(w.Body.Bytes(), want) {
					t.Fatal("candidates/signatures/unknown response fields changed")
				}
			} else if !strings.Contains(w.Body.String(), "preserve") {
				t.Fatal("upstream error was rewritten")
			}
		})
	}
}

func TestDiscoveryAndProjectIsolation(t *testing.T) {
	var projects atomic.Int32
	var account atomic.Int32
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1internal:loadCodeAssist":
			projects.Add(1)
			_, _ = io.WriteString(w, `{"cloudaicompanionProject":"private-project"}`)
		case "/v1internal:fetchAvailableModels":
			_, _ = io.WriteString(w, `{"models":{"gemini-new-medium":{"displayName":"New","maxTokens":1048576,"maxOutputTokens":262144},"gemini-new-high":{"displayName":"New high"},"claude-unverified":{"displayName":"Not Gemini"}}}`)
		default:
			t.Error("unexpected control request")
		}
	}, sourceFunc(func(context.Context) (credential, error) {
		return credential{AccessToken: "token-" + string(rune('a'+account.Load()))}, nil
	}))
	for i := 0; i < 2; i++ {
		w := request(p, "GET", "/v1beta/models", "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), "gemini-new-medium") || strings.Contains(w.Body.String(), "claude-unverified") || strings.Contains(w.Body.String(), "private-project") {
			t.Fatalf("bad discovery: %s", w.Body.String())
		}
	}
	if projects.Load() != 1 {
		t.Fatal("project was not cached")
	}
	account.Add(1)
	w := request(p, "GET", "/v1beta/models/gemini-new-medium", "")
	if projects.Load() != 2 || !strings.Contains(w.Body.String(), `"outputTokenLimit":262144`) {
		t.Fatal("account/project isolation or actual limit failed")
	}
	if request(p, "GET", "/v1beta/models/gemini-missing", "").Code != 404 {
		t.Fatal("invented model")
	}
}

type sourceFunc func(context.Context) (credential, error)

func (s sourceFunc) Load(ctx context.Context) (credential, error) { return s(ctx) }

func TestBodyLimitAndNoCredentialAccessForInvalidInput(t *testing.T) {
	var calls atomic.Int32
	p := testProxy(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) }, sourceFunc(func(context.Context) (credential, error) { calls.Add(1); return credential{}, errCredentials }))
	p.maxBody = 8
	if request(p, "POST", "/v1beta/models/gemini-test:generateContent", `{"tooLarge":true}`).Code != 413 {
		t.Fatal("body limit ignored")
	}
	if request(p, "POST", "/v1beta/models/gemini-test:generateContent", `null`).Code != 400 {
		t.Fatal("invalid JSON accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input accessed credentials/upstream")
	}
}

func TestRedirectDoesNotLeakBearer(t *testing.T) {
	var otherCalls atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { otherCalls.Add(1) }))
	defer other.Close()
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", other.URL)
		w.WriteHeader(307)
	}, fixedCredentials{credential{AccessToken: "private", Project: "p"}})
	w := request(p, "POST", "/v1beta/models/gemini-test:generateContent", `{}`)
	if w.Code != 307 || otherCalls.Load() != 0 || w.Header().Get("Location") != "" {
		t.Fatal("redirect followed or leaked")
	}
}

func TestStreamingCancellation(t *testing.T) {
	canceled := make(chan struct{})
	p := testProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"response\":{\"candidates\":[]}}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(canceled)
	}, fixedCredentials{credential{AccessToken: "private", Project: "p"}})
	server := httptest.NewServer(p)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/v1beta/models/gemini-test:streamGenerateContent?alt=sse", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+testKey)
	resp, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	_, _ = resp.Body.Read(b)
	cancel()
	resp.Body.Close()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("disconnect did not cancel upstream generation")
	}
}

func TestSSEMultilineAndNoSyntheticFinish(t *testing.T) {
	input := ": keepalive\r\nid: original\r\nevent: message\r\nretry: 25\r\ndata: {\"response\":\r\ndata: {\"candidates\":[{\"index\":0,\"content\":{\"parts\":[{\"text\":\"a\",\"thoughtSignature\":\"signature\"}]}},{\"index\":1}],\"unknown\":true},\"traceId\":\"outer\"}\r\n\r\ndata: {\"error\":{\"code\":429}}\n\ndata: [DONE]\n\n"
	var out bytes.Buffer
	flushes := 0
	if err := unwrapSSE(&out, strings.NewReader(input), func() { flushes++ }); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{": keepalive", "id: original", "event: message", "retry: 25", `"thoughtSignature":"signature"`, `"index":1`, `"unknown":true`, `"code":429`, "data: [DONE]"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(out.String(), "traceId") || strings.Contains(out.String(), "STOP") || flushes != 3 {
		t.Fatal("outer envelope or finish semantics wrong")
	}
	out.Reset()
	if err := unwrapSSE(&out, strings.NewReader("data: {\"response\":{}}"), func() {}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("truncated SSE accepted")
	}
	if err := unwrapSSE(&out, strings.NewReader("data: not-json\n\n"), func() {}); err == nil {
		t.Fatal("invalid SSE JSON accepted")
	}
	out.Reset()
	if err := unwrapSSE(&out, strings.NewReader("data: {\"response\":{\"candidates\":[]}}\n\n"), func() {}); err != nil || strings.Contains(out.String(), "STOP") {
		t.Fatal("clean EOF manufactured STOP")
	}
}

func TestCredentialFormatsAndPermissions(t *testing.T) {
	native := `{"token":{"access_token":"private","refresh_token":"never-use-or-log","token_type":"Bearer","expiry":"2099-01-01T00:00:00Z"},"auth_method":"consumer","id_token_email":"never-log"}`
	for _, data := range []string{native, "go-keyring-base64:" + base64.StdEncoding.EncodeToString([]byte(native)), `{"access_token":"private","expired":"2099-01-01T00:00:00Z","project_id":"p"}`} {
		c, err := decodeCredential([]byte(data))
		if err != nil || c.AccessToken != "private" || c.Expiry.Year() != 2099 {
			t.Fatalf("credential decoding failed: %v", err)
		}
	}
	for _, data := range []string{`{"access_token":"bad\nheader"}`, `{"token":{"access_token":"private"},"auth_method":"enterprise"}`, `{"access_token":"private","expiry":"invalid"}`, "not-a-token"} {
		if _, err := decodeCredential([]byte(data)); err == nil {
			t.Fatal("invalid credentials accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(native), 0644); err != nil {
		t.Fatal(err)
	}
	s := &localCredentials{file: path}
	if _, err := s.Load(context.Background()); err == nil {
		t.Fatal("world-readable credentials accepted")
	}
	_ = os.Chmod(path, 0600)
	if _, err := s.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(path, []byte(`{"access_token":"private","expiry":"2000-01-01T00:00:00Z"}`), 0600)
	if _, err := s.Load(context.Background()); err == nil {
		t.Fatal("expired credentials accepted")
	}
	filtered := withoutGateway([]string{"PATH=/bin", "CLOUD_CODE_URL=localhost", "AGY_LLM_GATEWAY_URL=localhost", "AGY_LLM_GATEWAY_API_KEY=private", "OTHER=yes"})
	if strings.Join(filtered, ";") != "PATH=/bin;OTHER=yes" {
		t.Fatal("native refresh could recurse into proxy")
	}
}
