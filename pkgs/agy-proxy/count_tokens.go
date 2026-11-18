package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// Code Assist's counter accepts richer JSON but silently ignores tools/system
// instructions. Reject those fields rather than advertise an exact request cost.
func countTokensEnvelope(data []byte, model string) ([]byte, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return nil, errors.New("countTokens requires a JSON object containing contents")
	}
	if raw, exists := fields["generateContentRequest"]; exists {
		var nested map[string]json.RawMessage
		if len(fields) != 1 || json.Unmarshal(raw, &nested) != nil || nested == nil {
			return nil, errors.New("generateContentRequest cannot be combined with contents")
		}
		fields = nested
	}
	for name := range fields {
		if name != "contents" && name != "model" {
			return nil, errors.New("this upstream counter measures contents only; system instructions, tools and other generation fields are not supported")
		}
	}
	if raw, exists := fields["model"]; exists {
		var requested string
		if json.Unmarshal(raw, &requested) != nil || strings.TrimPrefix(requested, "models/") != model {
			return nil, errors.New("countTokens model must match the URL model")
		}
	}
	var contents []json.RawMessage
	if json.Unmarshal(fields["contents"], &contents) != nil || len(contents) == 0 {
		return nil, errors.New("countTokens contents must be a nonempty array")
	}
	for _, raw := range contents {
		var content struct {
			Role  string            `json:"role"`
			Parts []json.RawMessage `json:"parts"`
		}
		if json.Unmarshal(raw, &content) != nil || len(content.Parts) == 0 || (content.Role != "" && content.Role != "user" && content.Role != "model") {
			return nil, errors.New("countTokens requires native Gemini contents and nonempty parts")
		}
		for _, part := range content.Parts {
			var object map[string]json.RawMessage
			if json.Unmarshal(part, &object) != nil || len(object) == 0 {
				return nil, errors.New("invalid native Gemini part")
			}
		}
	}
	return json.Marshal(map[string]any{"request": map[string]any{"model": "models/" + model, "contents": fields["contents"]}})
}

func (p *proxy) countTokens(w http.ResponseWriter, r *http.Request, model string) {
	body, err := readBody(w, r, p.maxBody)
	if err != nil {
		return
	}
	body, err = countTokensEnvelope(body, model)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	credential, err := p.source.Load(ctx)
	if err != nil {
		writeError(w, 503, errCredentials.Error())
		return
	}
	response, err := p.upstream(ctx, "countTokens", body, credential.AccessToken, model)
	if err != nil {
		writeUpstreamFailure(w, err, false)
		return
	}
	defer response.Body.Close()
	copyResponseHeaders(w.Header(), response.Header)
	w.Header().Set("Cache-Control", "no-store")
	if response.StatusCode != 200 {
		w.WriteHeader(response.StatusCode)
		if _, err := io.Copy(w, response.Body); err != nil {
			panic(http.ErrAbortHandler)
		}
		return
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, p.maxBody+1))
	var result struct {
		Total *int64          `json:"totalTokens"`
		Error json.RawMessage `json:"error"`
	}
	if err != nil || int64(len(data)) > p.maxBody || json.Unmarshal(data, &result) != nil || result.Total == nil || *result.Total < 0 || (len(result.Error) > 0 && !bytes.Equal(bytes.TrimSpace(result.Error), []byte("null"))) {
		writeError(w, 502, "upstream did not return a valid token count")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Agy-Count-Scope", "contents-only")
	_, _ = w.Write(data)
}
