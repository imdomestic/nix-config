package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type executorRequest struct {
	Model, SourceFormat, Alt string
	Payload, StorageJSON     []byte
	StreamID                 string `json:"stream_id"`
	CallbackID               string `json:"host_callback_id"`
}

var runtimeMu sync.Mutex
var stopping bool
var active sync.WaitGroup
var operations = map[string]string{}

func begin() *problem {
	runtimeMu.Lock()
	defer runtimeMu.Unlock()
	if stopping {
		return fail(503, "rewind_stopping", "Rewind plugin is stopping")
	}
	active.Add(1)
	return nil
}

func quiesce() {
	runtimeMu.Lock()
	stopping = true
	ops := make(map[string]string, len(operations))
	for id, cb := range operations {
		ops[id] = cb
	}
	runtimeMu.Unlock()
	for id, cb := range ops {
		cancelOperation(id, cb)
	}
	active.Wait()
}

func cancelOperation(id, cb string) {
	_ = callHost("host.http.cancel", map[string]string{"operation_id": id, "host_callback_id": cb}, nil)
}

func parseCredential(raw []byte) (credential, *problem) {
	var c credential
	if json.Unmarshal(raw, &c) != nil || c.Type != "rewind" || !filepath.IsAbs(c.APIKeyFile) || !filepath.IsAbs(c.DeviceFile) {
		return c, fail(400, "rewind_credential", "Invalid Rewind credential file")
	}
	return c, nil
}

func authData(raw []byte, id, file string, c credential) any {
	return map[string]any{"Provider": "rewind", "ID": id, "FileName": file, "Label": "Rewind", "Prefix": c.Prefix,
		"StorageJSON": raw, "Metadata": map[string]string{"type": "rewind"}, "NextRefreshAfter": time.Now().Add(24 * time.Hour)}
}

func modelResponse(enabled bool) any {
	models := []any{}
	if enabled {
		models = append(models, map[string]any{"ID": "gpt-6-astra", "Object": "model", "OwnedBy": "rewind", "DisplayName": "Rewind GPT-6 Astra",
			"ContextLength": 1050000, "MaxCompletionTokens": 96000, "SupportedGenerationMethods": []string{"chat"},
			"Thinking": map[string]any{"Levels": []string{"low", "medium", "high", "xhigh"}}})
	}
	return map[string]any{"Provider": "rewind", "Models": models}
}

func dispatch(method string, raw []byte) (any, *problem) {
	switch method {
	case "plugin.register", "plugin.reconfigure":
		return map[string]any{"schema_version": 6, "metadata": map[string]any{"Name": "rewind", "Version": "0.1.1", "Author": "imdomestic", "GitHubRepository": "https://github.com/imdomestic/nix-config", "ConfigFields": []any{}},
			"capabilities": map[string]any{"model_provider": true, "auth_provider": true, "executor": true, "executor_model_scope": "both",
				"executor_input_formats": []string{"responses"}, "executor_output_formats": []string{"responses"}}}, nil
	case "plugin.quiesce", "plugin.shutdown":
		quiesce()
		return map[string]any{}, nil
	case "executor.identifier", "auth.identifier":
		return map[string]string{"identifier": "rewind"}, nil
	case "model.static":
		return modelResponse(false), nil
	case "model.for_auth":
		return modelResponse(true), nil
	case "auth.parse":
		var req struct {
			RawJSON  []byte
			FileName string
		}
		if json.Unmarshal(raw, &req) != nil {
			return nil, fail(400, "invalid_request", "Invalid auth parse request")
		}
		var kind struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(req.RawJSON, &kind)
		if kind.Type != "rewind" {
			return map[string]bool{"Handled": false}, nil
		}
		c, e := parseCredential(req.RawJSON)
		if e != nil {
			return nil, e
		}
		return map[string]any{"Handled": true, "Auth": authData(req.RawJSON, req.FileName, req.FileName, c)}, nil
	case "auth.refresh":
		var req struct {
			StorageJSON []byte
			AuthID      string
		}
		if json.Unmarshal(raw, &req) != nil {
			return nil, fail(400, "invalid_request", "Invalid auth refresh request")
		}
		c, e := parseCredential(req.StorageJSON)
		if e != nil {
			return nil, e
		}
		return map[string]any{"Auth": authData(req.StorageJSON, req.AuthID, "", c), "NextRefreshAfter": time.Now().Add(24 * time.Hour)}, nil
	case "executor.execute", "executor.execute_stream":
		var req executorRequest
		if json.Unmarshal(raw, &req) != nil {
			return nil, fail(400, "invalid_request", "Invalid executor request")
		}
		if e := begin(); e != nil {
			return nil, e
		}
		stream, e := openExecution(req)
		if e != nil {
			active.Done()
			return nil, e
		}
		if method == "executor.execute_stream" {
			if req.StreamID == "" {
				stream.close()
				active.Done()
				return nil, fail(400, "invalid_request", "Missing plugin stream ID")
			}
			go func() {
				defer active.Done()
				defer stream.close()
				var terminalError *problem
				defer func() {
					if recover() != nil {
						terminalError = fail(500, "rewind_plugin_error", "Rewind stream failed")
					}
					_ = callHost("host.stream.close", map[string]any{"stream_id": req.StreamID, "error_detail": terminalError}, nil)
				}()
				_, terminalError = readSSE(stream, func(frame []byte) *problem {
					return callHost("host.stream.emit", map[string]any{"stream_id": req.StreamID, "payload": frame}, nil)
				})
			}()
			return map[string]any{"headers": http.Header{"Content-Type": {"text/event-stream"}, "Cache-Control": {"no-store"}}}, nil
		}
		defer active.Done()
		defer stream.close()
		body, e := readSSE(stream, nil)
		if e != nil {
			return nil, e
		}
		return map[string]any{"Payload": body, "Headers": http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}}, nil
	case "executor.count_tokens":
		return nil, fail(501, "not_supported", "Rewind does not expose a token counting endpoint")
	default:
		return nil, fail(400, "not_supported", "Unsupported Rewind plugin method")
	}
}

type upstreamStream struct {
	id, operation, callback string
	pending                 []byte
	timer                   *time.Timer
	read                    func(any, any) *problem
	closeOnce               sync.Once
	bytes                   int
}

func openExecution(req executorRequest) (*upstreamStream, *problem) {
	if req.SourceFormat != "openai-response" && req.SourceFormat != "responses" {
		return nil, fail(400, "invalid_request", "Rewind requires Responses input")
	}
	if req.Alt != "" {
		return nil, fail(400, "not_supported", "Rewind does not expose this alternate endpoint")
	}
	model := strings.TrimPrefix(req.Model, "rewind/")
	if model != "gpt-6-astra" {
		return nil, fail(404, "model_not_found", "Unknown Rewind model")
	}
	if len(req.Payload) > 32<<20 {
		return nil, fail(413, "invalid_request_error", "Rewind input is too large")
	}
	c, e := parseCredential(req.StorageJSON)
	if e != nil {
		return nil, e
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(req.Payload, &body) != nil || body == nil {
		return nil, fail(400, "invalid_request_error", "Invalid Responses payload")
	}
	body["model"], _ = json.Marshal(model)
	body["store"] = json.RawMessage("false")
	body["stream"] = json.RawMessage("true")
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fail(400, "invalid_request_error", "Invalid Responses payload")
	}
	client := getClient(c)
	headers, e := client.headers(rewindOrigin+"/v1/responses", data)
	if e != nil {
		return nil, e
	}
	var operation struct {
		ID string `json:"operation_id"`
	}
	if e := callHost("host.http.operation_open", map[string]string{"host_callback_id": req.CallbackID}, &operation); e != nil {
		return nil, e
	}
	s := &upstreamStream{operation: operation.ID, callback: req.CallbackID}
	runtimeMu.Lock()
	if stopping {
		runtimeMu.Unlock()
		cancelOperation(s.operation, s.callback)
		return nil, fail(503, "rewind_stopping", "Rewind plugin is stopping")
	}
	operations[s.operation] = s.callback
	runtimeMu.Unlock()
	s.timer = time.AfterFunc(45*time.Second, func() { cancelOperation(s.operation, s.callback) })
	var response struct {
		Status  int         `json:"status_code"`
		Headers http.Header `json:"headers"`
		ID      string      `json:"stream_id"`
	}
	e = callHost("host.http.do_stream", map[string]any{"host_callback_id": req.CallbackID, "operation_id": s.operation, "method": "POST",
		"url": rewindOrigin + "/v1/responses", "headers": headers, "body": data}, &response)
	s.id = response.ID
	if e != nil {
		s.close()
		return nil, e
	}
	s.read = func(value, result any) *problem { return callHost("host.http.stream_read", value, result) }
	s.timer.Reset(5 * time.Minute)
	if response.Status != 200 {
		raw, _ := io.ReadAll(io.LimitReader(s, 65536))
		s.close()
		if response.Status == 401 {
			client.invalidate()
		}
		return nil, upstreamProblem(response.Status, response.Headers, raw)
	}
	if !strings.Contains(response.Headers.Get("Content-Type"), "text/event-stream") {
		s.close()
		return nil, fail(502, "rewind_upstream", "Rewind returned an unexpected response format")
	}
	return s, nil
}

func (s *upstreamStream) Read(out []byte) (int, error) {
	for len(s.pending) == 0 {
		var r struct {
			Payload []byte `json:"payload"`
			Error   string `json:"error"`
			Done    bool   `json:"done"`
		}
		if e := s.read(map[string]string{"stream_id": s.id}, &r); e != nil {
			return 0, e
		}
		if r.Error != "" {
			return 0, fail(502, "rewind_transport", "Rewind stream interrupted")
		}
		if len(r.Payload) > 0 {
			s.bytes += len(r.Payload)
			if s.bytes > 32<<20 {
				return 0, fail(502, "rewind_transport", "Rewind response is too large")
			}
			s.pending = r.Payload
			if s.timer != nil {
				s.timer.Reset(5 * time.Minute)
			}
		} else if r.Done {
			return 0, io.EOF
		}
	}
	n := copy(out, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

func (s *upstreamStream) close() {
	s.closeOnce.Do(func() {
		if s.timer != nil {
			s.timer.Stop()
		}
		if s.id != "" {
			_ = callHost("host.http.stream_close", map[string]string{"stream_id": s.id}, nil)
		}
		cancelOperation(s.operation, s.callback)
		runtimeMu.Lock()
		delete(operations, s.operation)
		runtimeMu.Unlock()
	})
}

func readSSE(input io.Reader, emit func([]byte) *problem) ([]byte, *problem) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 65536), 32<<20)
	var frame, data bytes.Buffer
	for scanner.Scan() {
		line := scanner.Bytes()
		frame.Write(line)
		frame.WriteByte('\n')
		if bytes.HasPrefix(line, []byte("data:")) {
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.Write(bytes.TrimPrefix(line[5:], []byte(" ")))
		}
		if len(line) > 0 {
			continue
		}
		var event struct {
			Type     string          `json:"type"`
			Response json.RawMessage `json:"response"`
		}
		_ = json.Unmarshal(data.Bytes(), &event)
		if event.Type == "response.failed" || event.Type == "error" {
			raw := data.Bytes()
			if event.Type == "response.failed" {
				raw = event.Response
			}
			return nil, upstreamProblem(502, nil, raw)
		}
		if emit != nil {
			if e := emit(bytes.Clone(frame.Bytes())); e != nil {
				return nil, e
			}
		}
		if event.Type == "response.completed" || event.Type == "response.incomplete" {
			if len(event.Response) == 0 {
				return nil, fail(502, "rewind_transport", "Invalid terminal Responses event")
			}
			return bytes.Clone(event.Response), nil
		}
		frame.Reset()
		data.Reset()
	}
	return nil, fail(502, "rewind_transport", "Rewind stream ended before its terminal Responses event")
}
