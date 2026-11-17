package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

func chatError(w http.ResponseWriter, status int, message, kind string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": message, "type": kind, "param": nil, "code": status}})
}

func (p *proxy) chatRoute(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("X-Goog-Api-Key")
	if auth := r.Header.Get("Authorization"); auth != "" {
		if !strings.HasPrefix(auth, "Bearer ") || (key != "" && key != strings.TrimPrefix(auth, "Bearer ")) {
			chatError(w, 401, "invalid or conflicting proxy keys", "authentication_error")
			return
		}
		key = strings.TrimPrefix(auth, "Bearer ")
	}
	if p.key == "" || !p.authorized(key) {
		chatError(w, 401, "invalid proxy key", "authentication_error")
		return
	}
	if r.URL.RawQuery != "" {
		chatError(w, 400, "URL query parameters are not supported", "invalid_request_error")
		return
	}
	if r.Method == "GET" && (r.URL.Path == "/v1/models" || strings.HasPrefix(r.URL.Path, "/v1/models/")) {
		model := strings.TrimPrefix(r.URL.Path, "/v1/models")
		if model != "" {
			model = strings.TrimPrefix(model, "/")
			if !validModel(model) {
				chatError(w, 400, "invalid Gemini model ID", "invalid_request_error")
				return
			}
		}
		p.chatModels(w, r, model)
		return
	}
	if r.Method != "POST" || r.URL.Path != "/v1/chat/completions" {
		chatError(w, 404, "only Chat Completions and model discovery are supported", "invalid_request_error")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.maxBody))
	if err != nil {
		chatError(w, 413, "request body unavailable or too large", "invalid_request_error")
		return
	}
	input, err := decodeChatRequest(data)
	if err != nil {
		chatError(w, 400, err.Error(), "invalid_request_error")
		return
	}
	session := r.Header.Get("X-Agy-Session-Id")
	if other := r.Header.Get("X-Session-Id"); other != "" {
		if session != "" && session != other {
			chatError(w, 400, "conflicting session headers", "invalid_request_error")
			return
		}
		session = other
	}
	envelope, err := buildEnvelope(input.Gemini, input.Model, "", session, r.Header.Get("X-Agy-Request-Id"))
	if err != nil {
		chatError(w, 400, "invalid session or request header", "invalid_request_error")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	credential, project, err := p.credentials(ctx)
	cancel()
	if err != nil {
		chatError(w, 503, errCredentials.Error(), "server_error")
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
	response, err := p.upstream(r.Context(), action, envelope, credential.AccessToken)
	if err != nil {
		chatError(w, 502, "upstream transport failed; request was not replayed", "server_error")
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		chatUpstreamError(w, response)
		return
	}
	id, err := uuid()
	if err != nil {
		chatError(w, 500, "cannot allocate completion ID", "server_error")
		return
	}
	id = "chatcmpl-" + id
	created := time.Now().Unix()
	w.Header().Set("Cache-Control", "no-store")
	if input.Stream {
		if !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
			chatError(w, 502, "upstream did not return SSE", "server_error")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(200)
		controller := http.NewResponseController(w)
		if convertChatStream(w, response.Body, input.Model, id, created, input.IncludeUsage, func() { _ = controller.Flush() }) != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, p.maxBody+1))
	if err != nil || int64(len(data)) > p.maxBody {
		chatError(w, 502, "upstream response unavailable or too large", "server_error")
		return
	}
	data, err = convertChatJSON(data, input.Model, id, created)
	if err != nil {
		chatError(w, 502, "upstream returned an unsupported or incomplete Gemini response", "server_error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func chatUpstreamError(w http.ResponseWriter, response *http.Response) {
	if retry := response.Header.Get("Retry-After"); retry != "" {
		w.Header().Set("Retry-After", retry)
	}
	// Keep the raw Google JSON in details, while exposing the standard Chat error envelope.
	// Do not follow redirects or expose upstream cookies/Location headers.
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	var details json.RawMessage
	if err == nil && json.Valid(body) {
		details = body
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.StatusCode)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream rejected the request", "type": "upstream_error", "code": response.StatusCode, "details": details}})
}

func (p *proxy) chatModels(w http.ResponseWriter, r *http.Request, model string) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	credential, project, err := p.credentials(ctx)
	if err != nil {
		chatError(w, 503, errCredentials.Error(), "server_error")
		return
	}
	response, err := p.upstream(ctx, "fetchAvailableModels", chatRaw(map[string]string{"project": project}), credential.AccessToken)
	if err != nil {
		chatError(w, 502, "model discovery transport failed", "server_error")
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		chatUpstreamError(w, response)
		return
	}
	var catalog struct {
		Models map[string]struct {
			DisplayName string          `json:"displayName"`
			Context     json.RawMessage `json:"maxTokens"`
			Output      json.RawMessage `json:"maxOutputTokens"`
		} `json:"models"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, p.maxBody)).Decode(&catalog) != nil || catalog.Models == nil {
		chatError(w, 502, "invalid upstream model catalog", "server_error")
		return
	}
	ids := []string{}
	for id := range catalog.Models {
		if validModel(id) && (model == "" || model == id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	data := []map[string]any{}
	for _, id := range ids {
		info := catalog.Models[id]
		entry := map[string]any{"id": id, "object": "model", "created": 0, "owned_by": "google", "name": info.DisplayName}
		if len(info.Context) > 0 {
			entry["context_window"] = info.Context
		}
		if len(info.Output) > 0 {
			entry["max_output_tokens"] = info.Output
		}
		data = append(data, entry)
	}
	if model != "" && len(data) == 0 {
		chatError(w, 404, "model not available to this account", "invalid_request_error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if model != "" {
		_ = json.NewEncoder(w).Encode(data[0])
	} else {
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
	}
}
