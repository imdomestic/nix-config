package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Observed protocol profile and limitations: docs/agy-proxy.md.
const defaultUserAgent = "antigravity/cli/1.5.9 (aidev_client; os_type=darwin; arch=arm64; cl=1021519450; auth_method=consumer)"

var nativeMethods = map[string]bool{
	"loadCodeAssist": true, "fetchAvailableModels": true,
	"fetchAdminControls": true, "fetchUserInfo": true, "listExperiments": true,
	"retrieveUserQuotaSummary": true, "writeTrajectoryAcls": true,
	"generateContent": true, "streamGenerateContent": true, "countTokens": true,
}

type proxy struct {
	origin       *url.URL
	client       *http.Client
	native       *httputil.ReverseProxy
	source       credentialSource
	key          string
	userAgent    string
	maxBody      int64
	openaiCompat bool
	transportLog *log.Logger
	mu           sync.Mutex
	project      string
	identity     [32]byte
	projectAt    time.Time
}

func newProxy(origin *url.URL, transport http.RoundTripper, source credentialSource, key, ua string, maxBody int64) *proxy {
	p := &proxy{origin: origin, source: source, key: key, userAgent: ua, maxBody: maxBody, transportLog: newUpstreamLogger()}
	p.client = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	p.native = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(origin)
			r.Out.Host = origin.Host
			r.Out.GetBody = nil
			stripPrivateHeaders(r.Out.Header)
		},
		Transport: transport, FlushInterval: -1,
		ErrorLog: log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeError(w, 502, "upstream transport failed")
		},
	}
	return p
}

func stripPrivateHeaders(h http.Header) {
	for _, key := range []string{"X-Agy-Proxy-Key", "X-Agy-Session-Id", "X-Agy-Request-Id", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "Idempotency-Key", "X-Idempotency-Key"} {
		h.Del(key)
	}
}

func (p *proxy) authorized(value string) bool {
	return subtle.ConstantTimeCompare([]byte(value), []byte(p.key)) == 1
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"status\":\"ok\"}\n")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1internal:") {
		action := strings.TrimPrefix(r.URL.Path, "/v1internal:")
		if !nativeMethods[action] || r.Method != "POST" {
			writeError(w, 404, "unknown native method")
			return
		}
		if p.key != "" && !p.authorized(r.Header.Get("X-Agy-Proxy-Key")) {
			writeError(w, 401, "invalid proxy key")
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			writeError(w, 401, "native endpoint requires upstream Bearer authentication")
			return
		}
		if r.URL.RawQuery != "" && !(action == "streamGenerateContent" && r.URL.RawQuery == "alt=sse") {
			writeError(w, 400, "unsupported query")
			return
		}
		// Read the opaque body once. This also correctly accepts chunked clients.
		body, err := readBody(w, r, p.maxBody)
		if err != nil {
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.TransferEncoding = nil
		p.native.ServeHTTP(w, r)
		return
	}
	if p.source != nil && r.URL.Path == "/v1beta/capabilities" {
		p.capabilities(w, r)
		return
	}
	if p.source != nil && strings.HasPrefix(r.URL.Path, "/v1beta/") {
		if feature := unavailableAPI(r.URL.Path); feature != "" {
			p.unavailableRoute(w, r, feature)
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, "/v1/") && p.openaiCompat && p.source != nil {
		if r.URL.Path == "/v1/capabilities" {
			p.capabilities(w, r)
			return
		}
		if feature := unavailableAPI(r.URL.Path); feature != "" {
			p.unavailableRoute(w, r, feature)
			return
		}
		switch r.URL.Path {
		case "/v1/responses":
			p.responsesRoute(w, r)
		case "/v1/images/generations", "/v1/images/edits", "/v1/audio/transcriptions", "/v1/audio/translations":
			p.mediaRoute(w, r)
		default:
			p.chatRoute(w, r)
		}
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v1beta/models") || p.source == nil {
		writeError(w, 404, "unknown route")
		return
	}
	key := r.Header.Get("X-Goog-Api-Key")
	if authorization := r.Header.Get("Authorization"); authorization != "" {
		if !strings.HasPrefix(authorization, "Bearer ") || (key != "" && key != strings.TrimPrefix(authorization, "Bearer ")) {
			writeError(w, 401, "invalid or conflicting proxy keys")
			return
		}
		key = strings.TrimPrefix(authorization, "Bearer ")
	}
	if p.key == "" || !p.authorized(key) {
		writeError(w, 401, "invalid proxy key")
		return
	}
	suffix := strings.TrimPrefix(r.URL.Path, "/v1beta/models")
	if (suffix == "" || suffix == "/") && r.Method == "GET" {
		p.models(w, r, "")
		return
	}
	if !strings.HasPrefix(suffix, "/") || strings.Contains(strings.TrimPrefix(suffix, "/"), "/") {
		writeError(w, 404, "unknown route")
		return
	}
	model, action, hasAction := strings.Cut(strings.TrimPrefix(suffix, "/"), ":")
	if !validModel(model) {
		writeError(w, 400, "invalid model ID; use discovery IDs without aliases")
		return
	}
	if r.Method == "GET" && !hasAction {
		p.models(w, r, model)
		return
	}
	if r.Method != "POST" || !hasAction || (action != "generateContent" && action != "streamGenerateContent" && action != "countTokens") {
		writeError(w, 404, "unknown route")
		return
	}
	if r.URL.RawQuery != "" && !(action == "streamGenerateContent" && r.URL.RawQuery == "alt=sse") {
		writeError(w, 400, "unsupported query")
		return
	}
	if action == "countTokens" {
		p.countTokens(w, r, model)
		return
	}
	p.generate(w, r, model, action)
}

func validModel(model string) bool {
	if !strings.HasPrefix(model, "gemini-") || len(model) > 128 {
		return false
	}
	for _, c := range model {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, 413, "request body unavailable or too large")
	}
	return body, err
}

func (p *proxy) upstream(ctx context.Context, action string, body []byte, token string, models ...string) (*http.Response, error) {
	u := *p.origin
	u.Path = "/v1internal:" + action
	if action == "streamGenerateContent" {
		u.RawQuery = "alt=sse"
	}
	r, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.GetBody = nil // Generation POST is never automatically replayable.
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("User-Agent", p.userAgent)
	model := ""
	if len(models) > 0 {
		model = models[0]
	}
	return p.doUpstream(r, action, len(body), model)
}

func (p *proxy) projectFor(ctx context.Context, c credential) (string, error) {
	if c.Project != "" {
		return c.Project, nil
	}
	identity := sha256.Sum256([]byte(c.AccessToken))
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.identity == identity && p.project != "" && time.Since(p.projectAt) < 5*time.Minute {
		return p.project, nil
	}
	resp, err := p.upstream(ctx, "loadCodeAssist", []byte(`{"metadata":{"ideType":"ANTIGRAVITY"}}`), c.AccessToken)
	if err != nil {
		return "", errCredentials
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errCredentials
	}
	var data struct {
		Project json.RawMessage `json:"cloudaicompanionProject"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data) != nil {
		return "", errCredentials
	}
	var project string
	if json.Unmarshal(data.Project, &project) != nil {
		var object struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(data.Project, &object) == nil {
			project = object.ID
		}
	}
	if project == "" {
		// No implicit onboarding or subscription/credit mutation.
		return "", errCredentials
	}
	p.identity, p.project, p.projectAt = identity, project, time.Now()
	return project, nil
}

func (p *proxy) credentials(ctx context.Context) (credential, string, error) {
	c, err := p.source.Load(ctx)
	if err != nil {
		return credential{}, "", errCredentials
	}
	project, err := p.projectFor(ctx, c)
	return c, project, err
}

func buildEnvelope(body []byte, model, project, session, requestID string) ([]byte, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return nil, fmt.Errorf("request must be a Gemini JSON object")
	}
	if _, exists := fields["sessionId"]; !exists {
		if session == "" {
			var b [8]byte
			if _, err := rand.Read(b[:]); err != nil {
				return nil, err
			}
			session = "-" + strconv.FormatUint(binary.BigEndian.Uint64(b[:])&0x7fffffffffffffff, 10)
		}
		if len(session) > 256 || strings.ContainsAny(session, "\r\n") {
			return nil, fmt.Errorf("invalid session ID")
		}
		encoded, _ := json.Marshal(session)
		body = bytes.TrimSpace(body)
		separator := []byte(",")
		if len(fields) == 0 {
			separator = nil
		}
		body = append(append(append(append([]byte{}, body[:len(body)-1]...), separator...), []byte(`"sessionId":`)...), encoded...)
		body = append(body, '}')
	}
	if requestID == "" {
		a, err := uuid()
		if err != nil {
			return nil, err
		}
		b, err := uuid()
		if err != nil {
			return nil, err
		}
		requestID = fmt.Sprintf("agent/%s/%d/%s/1", a, time.Now().UnixMilli(), b)
	}
	if len(requestID) > 512 || strings.ContainsAny(requestID, "\r\n") {
		return nil, fmt.Errorf("invalid request ID")
	}
	requestType := "agent"
	if strings.Contains(model, "-image") {
		requestType = "image_gen"
	} else {
		var generation struct {
			Modalities []string `json:"responseModalities"`
		}
		if json.Unmarshal(fields["generationConfig"], &generation) == nil {
			for _, modality := range generation.Modalities {
				if modality == "IMAGE" {
					requestType = "image_gen"
					break
				}
			}
		}
	}
	return json.Marshal(struct {
		Project     string          `json:"project"`
		RequestID   string          `json:"requestId"`
		Request     json.RawMessage `json:"request"`
		Model       string          `json:"model"`
		UserAgent   string          `json:"userAgent"`
		RequestType string          `json:"requestType"`
	}{project, requestID, body, model, "antigravity", requestType})
}

func uuid() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func (p *proxy) generate(w http.ResponseWriter, r *http.Request, model, action string) {
	body, err := readBody(w, r, p.maxBody)
	if err != nil {
		return
	}
	// Validate before accessing credentials or sending any upstream request.
	envelope, err := buildEnvelope(body, model, "", r.Header.Get("X-Agy-Session-Id"), r.Header.Get("X-Agy-Request-Id"))
	if err != nil {
		writeError(w, 400, "invalid Gemini request or session headers")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	c, project, err := p.credentials(ctx)
	cancel()
	if err != nil {
		writeError(w, 503, errCredentials.Error())
		return
	}
	// Set the outer project without decoding or modifying the inner request.
	var outer map[string]json.RawMessage
	_ = json.Unmarshal(envelope, &outer)
	outer["project"], _ = json.Marshal(project)
	envelope, _ = json.Marshal(outer)
	resp, err := p.upstream(r.Context(), action, envelope, c.AccessToken, model)
	if err != nil {
		writeUpstreamFailure(w, err, false)
		return
	}
	defer resp.Body.Close()
	copyResponseHeaders(w.Header(), resp.Header)
	w.Header().Set("Cache-Control", "no-store")
	if resp.StatusCode != 200 {
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}
	if action == "streamGenerateContent" {
		if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			writeError(w, 502, "upstream did not return SSE")
			return
		}
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(200)
		controller := http.NewResponseController(w)
		if err := unwrapSSE(w, resp.Body, func() { _ = controller.Flush() }); err != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, p.maxBody+1))
	if err != nil || int64(len(data)) > p.maxBody {
		writeError(w, 502, "upstream response unavailable or too large")
		return
	}
	data, err = unwrapResponse(data)
	if err != nil {
		writeError(w, 502, "invalid upstream JSON")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func copyResponseHeaders(dst, src http.Header) {
	// Do not expose upstream cookies or credential-bearing redirect locations.
	for _, key := range []string{"Content-Type", "Retry-After", "Cache-Control", "X-Request-Id"} {
		for _, value := range src.Values(key) {
			dst.Add(key, value)
		}
	}
}

func (p *proxy) models(w http.ResponseWriter, r *http.Request, model string) {
	if r.URL.RawQuery != "" {
		writeError(w, 400, "model discovery currently returns the complete Gemini list without pagination")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	c, project, err := p.credentials(ctx)
	if err != nil {
		writeError(w, 503, errCredentials.Error())
		return
	}
	body, _ := json.Marshal(map[string]string{"project": project})
	resp, err := p.upstream(ctx, "fetchAvailableModels", body, c.AccessToken)
	if err != nil {
		writeError(w, 502, "model discovery transport failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	var catalog struct {
		Models map[string]struct {
			DisplayName      string          `json:"displayName"`
			InputTokenLimit  json.RawMessage `json:"maxTokens"`
			OutputTokenLimit json.RawMessage `json:"maxOutputTokens"`
		} `json:"models"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, p.maxBody)).Decode(&catalog) != nil || catalog.Models == nil {
		writeError(w, 502, "invalid upstream model catalog")
		return
	}
	ids := make([]string, 0, len(catalog.Models))
	for id := range catalog.Models {
		if validModel(id) && (model == "" || model == id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	models := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		info := catalog.Models[id]
		item := map[string]any{"name": "models/" + id, "displayName": info.DisplayName, "supportedGenerationMethods": []string{"generateContent", "streamGenerateContent", "countTokens"}}
		if len(info.InputTokenLimit) != 0 {
			item["inputTokenLimit"] = info.InputTokenLimit
		}
		if len(info.OutputTokenLimit) != 0 {
			item["outputTokenLimit"] = info.OutputTokenLimit
		}
		models = append(models, item)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if model != "" {
		if len(models) == 0 {
			writeError(w, 404, "model not available to this account")
			return
		}
		_ = json.NewEncoder(w).Encode(models[0])
	} else {
		_ = json.NewEncoder(w).Encode(map[string]any{"models": models})
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": status, "message": message}})
}
