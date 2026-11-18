package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// responsesRoute is deliberately stateless: there is no response store, lookup,
// previous_response_id, WebSocket transport, or automatic generation replay.
// The caller controls feature gating; this route still authenticates every call.
func (p *proxy) responsesRoute(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("X-Goog-Api-Key")
	if auth := r.Header.Get("Authorization"); auth != "" {
		if !strings.HasPrefix(auth, "Bearer ") || (key != "" && key != strings.TrimPrefix(auth, "Bearer ")) {
			responsesError(w, 401, "invalid or conflicting proxy keys", "authentication_error")
			return
		}
		key = strings.TrimPrefix(auth, "Bearer ")
	}
	if p.key == "" || !p.authorized(key) {
		responsesError(w, 401, "invalid proxy key", "authentication_error")
		return
	}
	if r.URL.RawQuery != "" {
		responsesError(w, 400, "URL query parameters are not supported", "invalid_request_error")
		return
	}
	if r.Method != "POST" || r.URL.Path != "/v1/responses" {
		responsesError(w, 404, "only stateless POST /v1/responses is supported", "invalid_request_error")
		return
	}
	if r.Header.Get("Upgrade") != "" {
		responsesError(w, 400, "Responses WebSocket upgrades are not supported", "invalid_request_error")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.maxBody))
	if err != nil {
		responsesError(w, 413, "request body unavailable or too large", "invalid_request_error")
		return
	}
	input, err := responsesDecodeRequest(data, p.key)
	if err != nil {
		responsesError(w, 400, err.Error(), "invalid_request_error")
		return
	}
	session := r.Header.Get("X-Agy-Session-Id")
	if other := r.Header.Get("X-Session-Id"); other != "" {
		if session != "" && session != other {
			responsesError(w, 400, "conflicting session headers", "invalid_request_error")
			return
		}
		session = other
	}
	envelope, err := buildEnvelope(input.Gemini, input.Model, "", session, r.Header.Get("X-Agy-Request-Id"))
	if err != nil {
		responsesError(w, 400, "invalid session or request header", "invalid_request_error")
		return
	}
	if p.source == nil {
		responsesError(w, 503, errCredentials.Error(), "server_error")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	credential, project, err := p.credentials(ctx)
	cancel()
	if err != nil {
		responsesError(w, 503, errCredentials.Error(), "server_error")
		return
	}
	var outer map[string]json.RawMessage
	_ = json.Unmarshal(envelope, &outer)
	outer["project"] = chatRaw(project)
	envelope = chatRaw(outer)
	action := "generateContent"
	if input.Stream {
		action = "streamGenerateContent"
	}
	response, err := p.upstream(r.Context(), action, envelope, credential.AccessToken, input.Model)
	if err != nil {
		writeUpstreamFailure(w, err, true)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		responsesUpstreamError(w, response, p.maxBody)
		return
	}
	id, err := uuid()
	if err != nil {
		responsesError(w, 500, "cannot allocate response ID", "server_error")
		return
	}
	id = "resp_" + id
	created := time.Now().Unix()
	w.Header().Set("Cache-Control", "no-store")
	if input.Stream {
		if !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
			responsesError(w, 502, "upstream did not return SSE", "server_error")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(200)
		controller := http.NewResponseController(w)
		if responsesConvertStream(w, response.Body, input, p.key, id, created, p.maxBody, func() { _ = controller.Flush() }) != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, p.maxBody+1))
	if err != nil || int64(len(data)) > p.maxBody {
		responsesError(w, 502, "upstream response unavailable or too large", "server_error")
		return
	}
	data, err = responsesConvertJSON(data, input, p.key, id, created, p.maxBody)
	if err != nil {
		responsesError(w, 502, "upstream returned an unsupported or incomplete Gemini response", "server_error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func responsesError(w http.ResponseWriter, status int, message, kind string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": message, "type": kind, "param": nil, "code": status}})
}

func responsesUpstreamError(w http.ResponseWriter, response *http.Response, limit int64) {
	if retry := response.Header.Get("Retry-After"); retry != "" {
		w.Header().Set("Retry-After", retry)
	}
	if limit > 1<<20 {
		limit = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	var details json.RawMessage
	if err == nil && int64(len(body)) <= limit && json.Valid(body) {
		details = body
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.StatusCode)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream rejected the request", "type": "upstream_error", "code": response.StatusCode, "details": details}})
}
