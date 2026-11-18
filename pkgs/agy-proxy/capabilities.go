package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

func (p *proxy) apiKeyAuthorized(r *http.Request) bool {
	key := r.Header.Get("X-Goog-Api-Key")
	if auth := r.Header.Get("Authorization"); auth != "" {
		if !strings.HasPrefix(auth, "Bearer ") || (key != "" && key != strings.TrimPrefix(auth, "Bearer ")) {
			return false
		}
		key = strings.TrimPrefix(auth, "Bearer ")
	}
	return p.key != "" && p.authorized(key)
}

func unavailableAPI(path string) string {
	if strings.HasPrefix(path, "/v1/responses/") {
		return "Responses server-side storage/actions"
	}
	for prefix, feature := range map[string]string{
		"/v1/files":              "Files upload/storage",
		"/v1/batches":            "asynchronous batch jobs",
		"/v1/embeddings":         "embeddings",
		"/v1/videos":             "video generation jobs",
		"/v1/audio/speech":       "speech generation",
		"/v1/realtime":           "realtime audio/video",
		"/v1beta/files":          "Gemini Files upload/storage",
		"/v1beta/cachedContents": "explicit context caching",
		"/v1beta/batches":        "asynchronous batch jobs",
		"/v1beta/operations":     "asynchronous operations",
	} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return feature
		}
	}
	if strings.HasPrefix(path, "/v1beta/models/") {
		_, method, ok := strings.Cut(strings.TrimPrefix(path, "/v1beta/models/"), ":")
		if ok {
			switch method {
			case "embedContent", "batchEmbedContents":
				return "embeddings"
			case "batchGenerateContent", "asyncBatchEmbedContent":
				return "asynchronous batch jobs"
			}
		}
	}
	return ""
}

func (p *proxy) unavailableRoute(w http.ResponseWriter, r *http.Request, feature string) {
	if !p.apiKeyAuthorized(r) {
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			chatError(w, 401, "invalid or conflicting proxy keys", "authentication_error")
		} else {
			writeError(w, 401, "invalid or conflicting proxy keys")
		}
		return
	}
	message := feature + " is not backed by this Antigravity subscription gateway; use a separately configured upstream that actually provides it"
	if strings.HasPrefix(r.URL.Path, "/v1/") {
		chatError(w, 501, message, "unsupported_api")
	} else {
		writeError(w, 501, message)
	}
}

func (p *proxy) capabilities(w http.ResponseWriter, r *http.Request) {
	if !p.apiKeyAuthorized(r) {
		writeError(w, 401, "invalid or conflicting proxy keys")
		return
	}
	if r.Method != "GET" || r.URL.RawQuery != "" {
		writeError(w, 400, "capabilities requires GET without query parameters")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"object": "agy.gateway.capabilities",
		"native": map[string]any{
			"generateContent": true, "streamGenerateContent": true,
			"countTokens":                 map[string]any{"scope": "contents-only", "system_instruction": false, "tools": false},
			"native_parts_and_signatures": "opaque passthrough",
		},
		"openai_compat_enabled": p.openaiCompat,
		"openai_compat": map[string]any{
			"chat_completions":     "stateless; native signature replay metadata required for tools",
			"responses":            "stateless; full-history input and gateway-encrypted reasoning replay",
			"images_generations":   "inline base64; real image-capable Gemini model required",
			"images_edits":         "multipart; no masks",
			"audio_transcriptions": "Gemini-mediated; file input; json or text only",
			"audio_translations":   "Gemini-mediated English translation; file input; json or text only",
		},
		"unsupported": []string{"Files storage/upload API", "explicit context cache", "batch jobs", "embeddings", "audio speech generation", "video generation jobs", "realtime/Bidi", "Responses storage/previous_response_id/WebSocket", "hosted tools"},
		"limits":      map[string]any{"request_bytes": p.maxBody, "remote_media_downloads": false, "automatic_generation_retries": false},
		"note":        "gateway implementation features, not per-model availability or subscription eligibility",
	})
}

// Keep safe errors independent of a caller-provided URL, field contents or tokens.
var errUnsupportedMultimodalTool = errors.New("unsupported multimodal tool result; use native Gemini parts when needed")
