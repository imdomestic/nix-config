package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const (
	chatResponseMaxCandidates = 32
	chatResponseMaxParts      = 65536
	chatResponseMaxTools      = 128
)

type chatResponseNativeCandidate struct {
	Index   *int `json:"index"`
	Content struct {
		Role  string            `json:"role"`
		Parts []json.RawMessage `json:"parts"`
	} `json:"content"`
	Finish string `json:"finishReason"`
}

type chatResponseNativeUsage struct {
	Prompt   *int64 `json:"promptTokenCount"`
	Output   *int64 `json:"candidatesTokenCount"`
	Thoughts *int64 `json:"thoughtsTokenCount"`
	Cached   *int64 `json:"cachedContentTokenCount"`
	Total    *int64 `json:"totalTokenCount"`
}

type chatResponseNativeFrame struct {
	Candidates []chatResponseNativeCandidate `json:"candidates"`
	Usage      chatResponseNativeUsage       `json:"usageMetadata"`
}

type chatResponseCandidate struct {
	parts       []json.RawMessage
	tools       []map[string]any
	text        strings.Builder
	thought     strings.Builder
	hasText     bool
	hasThought  bool
	started     bool
	finish      string
	nativeBytes int
}

type chatResponseState struct {
	model, id                 string
	created                   int64
	usage                     chatResponseNativeUsage
	candidates                map[int]*chatResponseCandidate
	order                     []int
	parts, tools, replayBytes int
}

func chatResponseNewState(model, id string, created int64) *chatResponseState {
	return &chatResponseState{model: model, id: id, created: created, candidates: make(map[int]*chatResponseCandidate)}
}

func chatResponseDecodeFrame(data []byte) (chatResponseNativeFrame, error) {
	var frame chatResponseNativeFrame
	if len(data) > maxEventBytes {
		return frame, errors.New("upstream Chat response too large")
	}
	// Check both levels: an envelope error must not be hidden by response.
	var object map[string]json.RawMessage
	for level := 0; level < 2; level++ {
		object = nil
		if json.Unmarshal(data, &object) != nil || object == nil {
			return frame, errors.New("invalid upstream Chat response")
		}
		if e, ok := object["error"]; ok && !bytes.Equal(bytes.TrimSpace(e), []byte("null")) {
			return frame, errors.New("upstream generation failed")
		}
		if feedback, ok := object["promptFeedback"]; ok {
			var check struct {
				Block string `json:"blockReason"`
			}
			if json.Unmarshal(feedback, &check) != nil {
				return frame, errors.New("invalid upstream prompt feedback")
			}
			if check.Block != "" {
				return frame, errors.New("upstream prompt blocked")
			}
		}
		if inner, ok := object["response"]; ok && level == 0 {
			data = inner
			continue
		}
		break
	}
	partsLeft := chatResponseMaxParts
	if _, err := chatResponseBoundArray(object["candidates"], chatResponseMaxCandidates, func(raw json.RawMessage) error {
		var candidate struct {
			Content struct {
				Parts json.RawMessage `json:"parts"`
			} `json:"content"`
		}
		if json.Unmarshal(raw, &candidate) != nil {
			return errors.New("invalid upstream candidate")
		}
		n, err := chatResponseBoundArray(candidate.Content.Parts, partsLeft, nil)
		partsLeft -= n
		return err
	}); err != nil {
		return frame, err
	}
	if json.Unmarshal(data, &frame) != nil {
		return frame, errors.New("invalid upstream Chat response")
	}
	return frame, nil
}

// Bound array allocation before unmarshaling the complete native frame.
func chatResponseBoundArray(raw json.RawMessage, limit int, visit func(json.RawMessage) error) (int, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return 0, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return 0, errors.New("invalid upstream Chat array")
	}
	count := 0
	for decoder.More() {
		if count >= limit {
			return count, errors.New("upstream Chat count limit exceeded")
		}
		var element json.RawMessage
		if decoder.Decode(&element) != nil {
			return count, errors.New("invalid upstream Chat array")
		}
		count++
		if visit != nil {
			if err := visit(element); err != nil {
				return count, err
			}
		}
	}
	return count, nil
}

func chatResponseFinish(reason string, tools bool) (string, error) {
	switch reason {
	case "STOP":
		if tools {
			return "tool_calls", nil
		}
		return "stop", nil
	case "MAX_TOKENS":
		return "length", nil
	case "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "LANGUAGE", "IMAGE_SAFETY", "IMAGE_PROHIBITED_CONTENT", "IMAGE_RECITATION":
		return "content_filter", nil
	default:
		return "", errors.New("unsupported upstream finish reason")
	}
}

func (s *chatResponseState) replay(c *chatResponseCandidate) map[string]any {
	parts := c.parts
	if parts == nil {
		parts = []json.RawMessage{}
	}
	return map[string]any{"model": s.model, "parts": parts}
}

func (s *chatResponseState) metadata(c *chatResponseCandidate, tool map[string]any) map[string]any {
	extra := map[string]any{"agy": s.replay(c)}
	if tool != nil {
		if old, ok := tool["extra_content"].(map[string]any); ok && old["google"] != nil {
			extra["google"] = old["google"]
		}
	}
	return extra
}

// A native functionCall is a complete call, never a textual argument prefix.
func chatResponsePart(raw json.RawMessage) (map[string]any, error) {
	var part map[string]json.RawMessage
	if json.Unmarshal(raw, &part) != nil || part == nil {
		return nil, errors.New("invalid upstream model part")
	}
	out := make(map[string]any)
	for key := range part {
		switch key {
		case "text", "thought", "thoughtSignature", "functionCall":
		default:
			// Unknown carriers are preserved on supported parts; unknown output
			// variants (including media) cannot be represented as Chat output.
			if key == "inlineData" || key == "fileData" || key == "executableCode" || key == "codeExecutionResult" || key == "functionResponse" || key == "videoMetadata" {
				return nil, errors.New("unsupported upstream Chat output part")
			}
		}
	}
	text, hasText := part["text"]
	call, hasCall := part["functionCall"]
	if hasText && hasCall {
		return nil, errors.New("ambiguous upstream model part")
	}
	if hasText {
		var value string
		var thought bool
		if json.Unmarshal(text, &value) != nil || bytes.Equal(bytes.TrimSpace(text), []byte("null")) {
			return nil, errors.New("invalid upstream text part")
		}
		if b, ok := part["thought"]; ok && json.Unmarshal(b, &thought) != nil {
			return nil, errors.New("invalid upstream thought part")
		}
		key := "content"
		if thought {
			key = "reasoning_content"
		}
		out[key] = value
	} else if hasCall {
		var fn struct {
			Name string          `json:"name"`
			ID   string          `json:"id"`
			Args json.RawMessage `json:"args"`
		}
		if json.Unmarshal(call, &fn) != nil || fn.Name == "" {
			return nil, errors.New("invalid upstream function call")
		}
		if len(fn.Args) == 0 {
			fn.Args = json.RawMessage(`{}`)
		}
		if trimmed := bytes.TrimSpace(fn.Args); len(trimmed) == 0 || trimmed[0] != '{' {
			return nil, errors.New("invalid upstream function arguments")
		}
		var compact bytes.Buffer
		if json.Compact(&compact, fn.Args) != nil {
			return nil, errors.New("invalid upstream function arguments")
		}
		if fn.ID == "" {
			id, err := uuid()
			if err != nil {
				return nil, errors.New("could not create Chat tool ID")
			}
			fn.ID = "call_" + id
		}
		tool := map[string]any{"id": fn.ID, "type": "function", "function": map[string]any{"name": fn.Name, "arguments": compact.String()}}
		if sig, ok := part["thoughtSignature"]; ok && !bytes.Equal(bytes.TrimSpace(sig), []byte("null")) {
			tool["extra_content"] = map[string]any{"google": map[string]any{"thought_signature": sig}}
		}
		out["tool"] = tool
	} else {
		if _, ok := part["thoughtSignature"]; !ok {
			return nil, errors.New("unsupported upstream Chat output part")
		}
		for key := range part {
			if key != "thought" && key != "thoughtSignature" {
				return nil, errors.New("unsupported upstream Chat output part")
			}
		}
	}
	return out, nil
}

func (s *chatResponseState) apply(frame chatResponseNativeFrame, emit func(int, map[string]any, any) error) error {
	if len(frame.Candidates) > chatResponseMaxCandidates {
		return errors.New("too many upstream Chat candidates")
	}
	targets := []**int64{&s.usage.Prompt, &s.usage.Output, &s.usage.Thoughts, &s.usage.Cached, &s.usage.Total}
	for i, value := range []*int64{frame.Usage.Prompt, frame.Usage.Output, frame.Usage.Thoughts, frame.Usage.Cached, frame.Usage.Total} {
		if value != nil {
			if *value < 0 {
				return errors.New("invalid upstream usage")
			}
			*targets[i] = value
		}
	}
	var sum int64
	for _, value := range []*int64{s.usage.Prompt, s.usage.Output, s.usage.Thoughts} {
		if value != nil {
			if *value > (1<<63-1)-sum {
				return errors.New("invalid upstream usage")
			}
			sum += *value
		}
	}
	seen := make(map[int]bool)
	for position, native := range frame.Candidates {
		index := position
		if native.Index != nil {
			index = *native.Index
		}
		if index < 0 || seen[index] || (native.Content.Role != "" && native.Content.Role != "model") {
			return errors.New("invalid upstream candidate")
		}
		seen[index] = true
		c := s.candidates[index]
		if c == nil {
			if len(s.candidates) >= chatResponseMaxCandidates {
				return errors.New("too many upstream Chat candidates")
			}
			c = &chatResponseCandidate{}
			s.candidates[index] = c
			s.order = append(s.order, index)
		}
		if c.finish != "" {
			return errors.New("upstream candidate continued after finish")
		}
		delta := make(map[string]any)
		if !c.started {
			delta["role"], c.started = "assistant", true
		}
		var tools []map[string]any
		var textDelta, thoughtDelta strings.Builder
		hasTextDelta, hasThoughtDelta := false, false
		for _, raw := range native.Content.Parts {
			if s.parts >= chatResponseMaxParts {
				return errors.New("too many upstream Chat parts")
			}
			part, err := chatResponsePart(raw)
			if err != nil {
				return err
			}
			toolCount := len(c.tools)
			if part["tool"] != nil {
				if s.tools >= chatResponseMaxTools {
					return errors.New("too many upstream Chat tools")
				}
				s.tools++
				toolCount++
			}
			// Count repeated replay on every tool too, before marshaling it.
			newBytes := c.nativeBytes + len(raw)
			available := maxEventBytes - s.replayBytes + c.nativeBytes*(len(c.tools)+1)
			if newBytes > available/(toolCount+1) {
				return errors.New("upstream Chat replay too large")
			}
			s.replayBytes += newBytes*(toolCount+1) - c.nativeBytes*(len(c.tools)+1)
			c.nativeBytes = newBytes
			s.parts++
			c.parts = append(c.parts, raw)
			if value, ok := part["content"].(string); ok {
				c.text.WriteString(value)
				textDelta.WriteString(value)
				c.hasText, hasTextDelta = true, true
			}
			if value, ok := part["reasoning_content"].(string); ok {
				c.thought.WriteString(value)
				thoughtDelta.WriteString(value)
				c.hasThought, hasThoughtDelta = true, true
			}
			if tool, ok := part["tool"].(map[string]any); ok {
				tool["index"] = len(c.tools)
				c.tools = append(c.tools, tool)
				tools = append(tools, tool)
			}
		}
		if hasTextDelta {
			delta["content"] = textDelta.String()
		}
		if hasThoughtDelta {
			delta["reasoning_content"] = thoughtDelta.String()
		}
		if len(tools) > 0 {
			delta["tool_calls"] = tools
		}
		if native.Finish != "" {
			var err error
			c.finish, err = chatResponseFinish(native.Finish, len(c.tools) > 0)
			if err != nil {
				return err
			}
		}
		if len(delta) > 0 {
			if err := emit(index, delta, nil); err != nil {
				return err
			}
		}
		if c.finish != "" {
			terminal := map[string]any{"extra_content": s.metadata(c, nil)}
			if len(c.tools) > 0 {
				var metadata []map[string]any
				for i, tool := range c.tools {
					metadata = append(metadata, map[string]any{"index": i, "extra_content": s.metadata(c, tool)})
				}
				terminal["tool_calls"] = metadata
			}
			if err := emit(index, terminal, c.finish); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *chatResponseState) validate() error {
	if len(s.candidates) == 0 {
		return errors.New("upstream returned no Chat candidates")
	}
	for _, c := range s.candidates {
		if c.finish == "" {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func (s *chatResponseState) usageJSON() map[string]any {
	value := func(n *int64) int64 {
		if n == nil {
			return 0
		}
		return *n
	}
	prompt, output := value(s.usage.Prompt), value(s.usage.Output)+value(s.usage.Thoughts)
	total := prompt + output
	if s.usage.Total != nil {
		total = *s.usage.Total
	}
	return map[string]any{"prompt_tokens": prompt, "completion_tokens": output, "total_tokens": total,
		"completion_tokens_details": map[string]any{"reasoning_tokens": value(s.usage.Thoughts)},
		"prompt_tokens_details":     map[string]any{"cached_tokens": value(s.usage.Cached)}}
}

func (s *chatResponseState) envelope(object string, choices []any) map[string]any {
	return map[string]any{"id": s.id, "object": object, "created": s.created, "model": s.model, "choices": choices}
}

func convertChatJSON(data []byte, model, id string, created int64) ([]byte, error) {
	frame, err := chatResponseDecodeFrame(data)
	if err != nil {
		return nil, err
	}
	s := chatResponseNewState(model, id, created)
	if err := s.apply(frame, func(int, map[string]any, any) error { return nil }); err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	choices := make([]any, 0, len(s.order))
	for _, index := range s.order {
		c := s.candidates[index]
		message := map[string]any{"role": "assistant", "content": nil, "extra_content": s.metadata(c, nil)}
		if c.hasText {
			message["content"] = c.text.String()
		}
		if c.hasThought {
			message["reasoning_content"] = c.thought.String()
		}
		if len(c.tools) > 0 {
			tools := make([]map[string]any, 0, len(c.tools))
			for _, tool := range c.tools {
				tools = append(tools, map[string]any{"id": tool["id"], "type": "function", "function": tool["function"], "extra_content": s.metadata(c, tool)})
			}
			message["tool_calls"] = tools
		}
		choices = append(choices, map[string]any{"index": index, "message": message, "finish_reason": c.finish})
	}
	result := s.envelope("chat.completion", choices)
	result["usage"] = s.usageJSON()
	return json.Marshal(result)
}

// chatResponseSSELine accepts all SSE line endings, including split CRLF.
func chatResponseSSELine(data []byte, atEOF bool) (int, []byte, error) {
	for i, b := range data {
		if b == '\n' {
			return i + 1, data[:i], nil
		}
		if b == '\r' {
			if i+1 == len(data) && !atEOF {
				return 0, nil, nil
			}
			n := i + 1
			if n < len(data) && data[n] == '\n' {
				n++
			}
			return n, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		return 0, nil, io.ErrUnexpectedEOF
	}
	return 0, nil, nil
}

func chatResponseWriteSSE(dst io.Writer, event string) error {
	if n, err := io.WriteString(dst, event); err != nil || n != len(event) {
		return errors.New("Chat stream write failed")
	}
	return nil
}

func convertChatStream(dst io.Writer, src io.Reader, model, id string, created int64, includeUsage bool, flush func()) (retErr error) {
	defer func() {
		if retErr != nil {
			_ = chatResponseWriteSSE(dst, "data: {\"error\":{\"message\":\"upstream Chat translation failed\",\"type\":\"upstream_error\",\"code\":\"upstream_error\"}}\n\n")
			if flush != nil {
				flush()
			}
		}
	}()
	s := chatResponseNewState(model, id, created)
	write := func(value any) error {
		data, err := json.Marshal(value)
		if err != nil {
			return errors.New("could not encode Chat response")
		}
		if err := chatResponseWriteSSE(dst, "data: "+string(data)+"\n\n"); err != nil {
			return err
		}
		if flush != nil {
			flush()
		}
		return nil
	}
	emit := func(index int, delta map[string]any, finish any) error {
		return write(s.envelope("chat.completion.chunk", []any{map[string]any{"index": index, "delta": delta, "finish_reason": finish}}))
	}
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 64<<10), maxEventBytes+2)
	lineBytes := 0
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		n, token, err := chatResponseSSELine(data, atEOF)
		lineBytes = n
		return n, token, err
	})
	var data strings.Builder
	hasData := false
	size, pending, first, done := 0, false, true, false
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			line, first = strings.TrimPrefix(line, "\ufeff"), false
		}
		if line == "" {
			if hasData {
				payload := data.String()
				if done {
					return errors.New("upstream data after stream end")
				}
				if payload == "[DONE]" {
					if err := s.validate(); err != nil {
						return err
					}
					done = true
				} else {
					frame, err := chatResponseDecodeFrame([]byte(payload))
					if err != nil {
						return err
					}
					if err := s.apply(frame, emit); err != nil {
						return err
					}
				}
			}
			data.Reset()
			hasData, size, pending = false, 0, false
			continue
		}
		pending, size = true, size+lineBytes
		if size > maxEventBytes-s.replayBytes {
			return errors.New("upstream SSE event or replay too large")
		}
		field, value, _ := strings.Cut(line, ":")
		if field == "data" {
			if hasData {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(value, " "))
			hasData = true
		}
	}
	if scanner.Err() != nil {
		return errors.New("upstream Chat stream read failed or truncated")
	}
	if pending {
		return io.ErrUnexpectedEOF
	}
	if err := s.validate(); err != nil {
		return err
	}
	if includeUsage {
		frame := s.envelope("chat.completion.chunk", []any{})
		frame["usage"] = s.usageJSON()
		if err := write(frame); err != nil {
			return err
		}
	}
	if err := chatResponseWriteSSE(dst, "data: [DONE]\n\n"); err != nil {
		return err
	}
	if flush != nil {
		flush()
	}
	return nil
}
