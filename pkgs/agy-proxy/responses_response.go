package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

type responsesState struct {
	input          responsesInput
	key, id        string
	created        int64
	limit          int64
	parts          []json.RawMessage
	nativeBytes    int64
	tools          int
	finish         string
	items          []map[string]any
	textIndex      int
	text           strings.Builder
	summary        strings.Builder
	summaryStarted bool
	usage          *chatResponseState
	usedCalls      map[string]bool
	emit           func(string, map[string]any) error
}

func responsesNewState(input responsesInput, key, id string, created, limit int64, emit func(string, map[string]any) error) *responsesState {
	return &responsesState{input: input, key: key, id: id, created: created, limit: limit, textIndex: -1, usage: chatResponseNewState(input.Model, id, created), usedCalls: map[string]bool{}, emit: emit}
}

func (s *responsesState) event(kind string, fields map[string]any) error {
	if s.emit == nil {
		return nil
	}
	return s.emit(kind, fields)
}

func (s *responsesState) base(status string) map[string]any {
	output := s.items
	if output == nil {
		output = []map[string]any{}
	}
	metadata := s.input.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	return map[string]any{"id": s.id, "object": "response", "created_at": s.created, "status": status, "model": s.input.Model, "output": output, "store": false, "background": false, "error": nil, "incomplete_details": nil, "usage": nil, "metadata": metadata, "parallel_tool_calls": true, "tool_choice": s.input.ToolChoice, "truncation": "disabled"}
}

func (s *responsesState) start() error {
	if err := s.event("response.created", map[string]any{"response": s.base("in_progress")}); err != nil {
		return err
	}
	if err := s.event("response.in_progress", map[string]any{"response": s.base("in_progress")}); err != nil {
		return err
	}
	item := map[string]any{"id": "rs_" + strings.TrimPrefix(s.id, "resp_"), "type": "reasoning", "summary": []any{}}
	s.items = append(s.items, item)
	return s.event("response.output_item.added", map[string]any{"output_index": 0, "item": item})
}

func (s *responsesState) partEvent(kind string, index int, part map[string]any) error {
	return s.event(kind, map[string]any{"item_id": s.items[index]["id"], "output_index": index, "content_index": 0, "part": part})
}

func (s *responsesState) textPart() map[string]any {
	return map[string]any{"type": "output_text", "text": s.text.String(), "annotations": []any{}, "logprobs": []any{}}
}

func (s *responsesState) closeText(status string) error {
	if s.textIndex < 0 {
		return nil
	}
	index := s.textIndex
	item := s.items[index]
	part := s.textPart()
	item["content"] = []any{part}
	item["status"] = status
	if err := s.event("response.output_text.done", map[string]any{"item_id": item["id"], "output_index": index, "content_index": 0, "text": s.text.String(), "logprobs": []any{}}); err != nil {
		return err
	}
	if err := s.partEvent("response.content_part.done", index, part); err != nil {
		return err
	}
	if err := s.event("response.output_item.done", map[string]any{"output_index": index, "item": item}); err != nil {
		return err
	}
	s.textIndex = -1
	s.text.Reset()
	return nil
}

func (s *responsesState) addText(text string) error {
	if s.textIndex < 0 {
		s.textIndex = len(s.items)
		s.text.Reset()
		item := map[string]any{"id": fmt.Sprintf("msg_%s_%d", strings.TrimPrefix(s.id, "resp_"), s.textIndex), "type": "message", "role": "assistant", "status": "in_progress", "content": []any{}}
		s.items = append(s.items, item)
		if err := s.event("response.output_item.added", map[string]any{"output_index": s.textIndex, "item": item}); err != nil {
			return err
		}
		if err := s.partEvent("response.content_part.added", s.textIndex, s.textPart()); err != nil {
			return err
		}
	}
	s.text.WriteString(text)
	return s.event("response.output_text.delta", map[string]any{"item_id": s.items[s.textIndex]["id"], "output_index": s.textIndex, "content_index": 0, "delta": text, "logprobs": []any{}})
}

func (s *responsesState) addSummary(text string) error {
	if !s.summaryStarted {
		s.summaryStarted = true
		if err := s.event("response.reasoning_summary_part.added", map[string]any{"item_id": s.items[0]["id"], "output_index": 0, "summary_index": 0, "part": map[string]any{"type": "summary_text", "text": ""}}); err != nil {
			return err
		}
	}
	s.summary.WriteString(text)
	return s.event("response.reasoning_summary_text.delta", map[string]any{"item_id": s.items[0]["id"], "output_index": 0, "summary_index": 0, "delta": text})
}

func (s *responsesState) addCall(tool map[string]any) error {
	if s.tools >= chatResponseMaxTools {
		return errors.New("too many upstream function calls")
	}
	s.tools++
	if err := s.closeText("completed"); err != nil {
		return err
	}
	function := tool["function"].(map[string]any)
	callID := tool["id"].(string)
	if s.usedCalls[callID] {
		return errors.New("duplicate upstream function call ID")
	}
	s.usedCalls[callID] = true
	index := len(s.items)
	item := map[string]any{"id": fmt.Sprintf("fc_%s_%d", strings.TrimPrefix(s.id, "resp_"), index), "type": "function_call", "call_id": callID, "name": function["name"], "arguments": "", "status": "in_progress"}
	s.items = append(s.items, item)
	if err := s.event("response.output_item.added", map[string]any{"output_index": index, "item": item}); err != nil {
		return err
	}
	arguments := function["arguments"].(string)
	// Gemini sends complete JSON functionCall objects, not argument prefixes. A
	// delta is emitted immediately for each arriving native call (never at EOF).
	if err := s.event("response.function_call_arguments.delta", map[string]any{"item_id": item["id"], "output_index": index, "delta": arguments}); err != nil {
		return err
	}
	item["arguments"] = arguments
	item["status"] = "completed"
	if err := s.event("response.function_call_arguments.done", map[string]any{"item_id": item["id"], "output_index": index, "arguments": arguments, "name": item["name"]}); err != nil {
		return err
	}
	return s.event("response.output_item.done", map[string]any{"output_index": index, "item": item})
}

func responsesNativePart(raw json.RawMessage) (map[string]any, error) {
	var part map[string]json.RawMessage
	if json.Unmarshal(raw, &part) != nil || part == nil {
		return nil, errors.New("invalid upstream model part")
	}
	if signature, ok := part["thoughtSignature"]; ok {
		var value string
		if json.Unmarshal(signature, &value) != nil || responsesNull(signature) {
			return nil, errors.New("invalid upstream signature carrier")
		}
	}
	if thought, ok := part["thought"]; ok {
		var value bool
		if json.Unmarshal(thought, &value) != nil || responsesNull(thought) {
			return nil, errors.New("invalid upstream thought flag")
		}
	}
	for _, name := range []string{"inlineData", "fileData", "executableCode", "codeExecutionResult", "functionResponse", "videoMetadata"} {
		if _, ok := part[name]; ok {
			return nil, errors.New("unsupported upstream Responses output part")
		}
	}
	_, text := part["text"]
	_, call := part["functionCall"]
	if !text && !call {
		// Signature-only parts and future opaque fields on those carriers belong to
		// the turn, even though there is no public Responses content to emit.
		if _, ok := part["thoughtSignature"]; ok {
			return map[string]any{}, nil
		}
		return nil, errors.New("unsupported upstream Responses output variant")
	}
	if call {
		var fn struct {
			Args json.RawMessage `json:"args"`
		}
		if json.Unmarshal(part["functionCall"], &fn) != nil {
			return nil, errors.New("invalid upstream function call")
		}
		if len(fn.Args) > 0 && responsesCheckJSON(fn.Args) != nil {
			return nil, errors.New("invalid or duplicate upstream function arguments")
		}
	}
	return chatResponsePart(raw)
}

func (s *responsesState) apply(frame chatResponseNativeFrame) error {
	if len(frame.Candidates) > 1 {
		return errors.New("Responses supports exactly one upstream candidate, not multiple choices")
	}
	if err := s.usage.apply(chatResponseNativeFrame{Usage: frame.Usage}, func(int, map[string]any, any) error { return nil }); err != nil {
		return err
	}
	if len(frame.Candidates) == 0 {
		return nil
	}
	candidate := frame.Candidates[0]
	if (candidate.Index != nil && *candidate.Index != 0) || (candidate.Content.Role != "" && candidate.Content.Role != "model") {
		return errors.New("Responses supports only upstream candidate zero")
	}
	if s.finish != "" {
		return errors.New("upstream candidate continued after finish")
	}
	for _, raw := range candidate.Content.Parts {
		if len(s.parts) >= chatResponseMaxParts {
			return errors.New("too many upstream model parts")
		}
		if int64(len(raw)) > s.limit-s.nativeBytes || s.nativeBytes+int64(len(raw)) > maxEventBytes {
			return errors.New("aggregate native Responses output too large")
		}
		part, err := responsesNativePart(raw)
		if err != nil {
			return err
		}
		s.parts = append(s.parts, raw)
		s.nativeBytes += int64(len(raw))
		if value, ok := part["content"].(string); ok {
			if err = s.addText(value); err != nil {
				return err
			}
		}
		if value, ok := part["reasoning_content"].(string); ok {
			if err = s.addSummary(value); err != nil {
				return err
			}
		}
		if tool, ok := part["tool"].(map[string]any); ok {
			if err = s.addCall(tool); err != nil {
				return err
			}
		}
	}
	if candidate.Finish != "" {
		finish, err := chatResponseFinish(candidate.Finish, s.tools > 0)
		if err != nil {
			return err
		}
		s.finish = finish
	}
	return nil
}

func (s *responsesState) validate() error {
	if s.finish == "" {
		return io.ErrUnexpectedEOF
	}
	if len(s.parts) == 0 {
		return errors.New("upstream returned no model parts")
	}
	return nil
}

func (s *responsesState) complete() (map[string]any, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	status := "completed"
	reason := ""
	if s.finish == "length" {
		status, reason = "incomplete", "max_output_tokens"
	} else if s.finish == "content_filter" {
		status, reason = "incomplete", "content_filter"
	}
	if err := s.closeText(status); err != nil {
		return nil, err
	}
	reasoning := s.items[0]
	if s.summaryStarted {
		part := map[string]any{"type": "summary_text", "text": s.summary.String()}
		reasoning["summary"] = []any{part}
		if err := s.event("response.reasoning_summary_text.done", map[string]any{"item_id": reasoning["id"], "output_index": 0, "summary_index": 0, "text": s.summary.String()}); err != nil {
			return nil, err
		}
		if err := s.event("response.reasoning_summary_part.done", map[string]any{"item_id": reasoning["id"], "output_index": 0, "summary_index": 0, "part": part}); err != nil {
			return nil, err
		}
	}
	if s.input.Encrypted {
		turn := responsesTurn{Model: s.input.Model, Context: s.input.Context, Parts: s.parts, ReasoningID: reasoning["id"].(string), Summary: s.summary.String()}
		for _, item := range s.items[1:] {
			visible := responsesVisible{Type: item["type"].(string), ID: item["id"].(string)}
			if visible.Type == "message" {
				part := item["content"].([]any)[0].(map[string]any)
				visible.Text = part["text"].(string)
			} else {
				visible.Name = item["name"].(string)
				visible.CallID = item["call_id"].(string)
				var err error
				visible.Arguments, err = responsesCanonical([]byte(item["arguments"].(string)))
				if err != nil {
					return nil, err
				}
			}
			turn.Items = append(turn.Items, visible)
		}
		blob, err := responsesEncryptBound(s.key, turn, s.limit)
		if err != nil {
			return nil, err
		}
		if len(blob) > maxEventBytes {
			return nil, errors.New("encrypted replay output too large")
		}
		reasoning["encrypted_content"] = blob
	}
	if err := s.event("response.output_item.done", map[string]any{"output_index": 0, "item": reasoning}); err != nil {
		return nil, err
	}
	response := s.base(status)
	usage := s.usage.usageJSON()
	response["usage"] = map[string]any{"input_tokens": usage["prompt_tokens"], "output_tokens": usage["completion_tokens"], "total_tokens": usage["total_tokens"], "input_tokens_details": usage["prompt_tokens_details"], "output_tokens_details": usage["completion_tokens_details"]}
	if reason != "" {
		response["incomplete_details"] = map[string]any{"reason": reason}
	}
	return response, nil
}

func responsesConvertJSON(data []byte, input responsesInput, key, id string, created, limit int64) ([]byte, error) {
	if int64(len(data)) > limit {
		return nil, errors.New("upstream Responses JSON too large")
	}
	if err := responsesCheckJSON(data); err != nil {
		return nil, err
	}
	frame, err := chatResponseDecodeFrame(data)
	if err != nil {
		return nil, err
	}
	state := responsesNewState(input, key, id, created, limit, nil)
	if err = state.start(); err != nil {
		return nil, err
	}
	if err = state.apply(frame); err != nil {
		return nil, err
	}
	response, err := state.complete()
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(response)
	if err == nil && int64(len(out)) > limit {
		return nil, errors.New("aggregate Responses output too large")
	}
	return out, err
}

// A bound on the entire native stream also bounds never-ending comment-only
// events. Reading one extra byte distinguishes a valid exact-limit EOF.
type responsesBoundReader struct {
	src  io.Reader
	left int64
}

func (r *responsesBoundReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		var extra [1]byte
		n, err := r.src.Read(extra[:])
		if n > 0 {
			return 0, errors.New("upstream Responses stream too large")
		}
		return 0, err
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	n, err := r.src.Read(p)
	r.left -= int64(n)
	return n, err
}

func responsesConvertStream(dst io.Writer, src io.Reader, input responsesInput, key, id string, created, limit int64, flush func()) (retErr error) {
	var sequence, written int64
	var state *responsesState
	write := func(kind string, fields map[string]any) error {
		fields["type"], fields["sequence_number"] = kind, sequence
		sequence++
		data, err := json.Marshal(fields)
		if err != nil {
			return errors.New("cannot encode Responses event")
		}
		event := "event: " + kind + "\ndata: " + string(data) + "\n\n"
		if len(event) > maxEventBytes || int64(len(event)) > limit-written {
			return errors.New("aggregate Responses event output too large")
		}
		written += int64(len(event))
		n, err := io.WriteString(dst, event)
		if err != nil || n != len(event) {
			return errors.New("Responses stream write failed")
		}
		if flush != nil {
			flush()
		}
		return nil
	}
	defer func() {
		if retErr != nil {
			failure := map[string]any{"code": "upstream_error", "message": "upstream Responses translation failed", "param": nil}
			_ = write("error", map[string]any{"code": "upstream_error", "message": "upstream Responses translation failed", "param": nil})
			if state != nil {
				response := state.base("failed")
				response["error"] = failure
				_ = write("response.failed", map[string]any{"response": response})
			}
		}
	}()
	state = responsesNewState(input, key, id, created, limit, write)
	if err := state.start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(&responsesBoundReader{src: src, left: limit})
	eventLimit := int64(maxEventBytes)
	if limit < eventLimit {
		eventLimit = limit
	}
	if eventLimit < 1 {
		return errors.New("invalid Responses stream limit")
	}
	scanner.Buffer(make([]byte, 4096), int(eventLimit)+2)
	lineBytes := 0
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		n, token, err := chatResponseSSELine(data, atEOF)
		lineBytes = n
		return n, token, err
	})
	var payload strings.Builder
	first, pending, hasData, done := true, false, false, false
	size := 0
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			line = strings.TrimPrefix(line, "\ufeff")
			first = false
		}
		if line == "" {
			if hasData {
				if done {
					return errors.New("upstream data after stream end")
				}
				if payload.String() == "[DONE]" {
					if err := state.validate(); err != nil {
						return err
					}
					done = true
				} else {
					if err := responsesCheckJSON([]byte(payload.String())); err != nil {
						return err
					}
					frame, err := chatResponseDecodeFrame([]byte(payload.String()))
					if err != nil {
						return err
					}
					if err = state.apply(frame); err != nil {
						return err
					}
				}
			}
			payload.Reset()
			pending, hasData = false, false
			size = 0
			continue
		}
		pending = true
		size += lineBytes
		if int64(size) > eventLimit {
			return errors.New("upstream Responses SSE event too large")
		}
		field, value, _ := strings.Cut(line, ":")
		if field == "data" {
			if hasData {
				payload.WriteByte('\n')
			}
			payload.WriteString(strings.TrimPrefix(value, " "))
			hasData = true
		}
		// Native error events are failures even if they contain no data field.
		if field == "event" && strings.TrimSpace(value) == "error" {
			return errors.New("upstream SSE error event")
		}
	}
	if scanner.Err() != nil {
		return errors.New("upstream Responses stream read failed or truncated")
	}
	if pending {
		return io.ErrUnexpectedEOF
	}
	response, err := state.complete()
	if err != nil {
		return err
	}
	// Native STOP alone is insufficient: only clean EOF, after all native events
	// (including trailing usage), permits a completed/incomplete lifecycle event.
	return write("response."+response["status"].(string), map[string]any{"response": response})
}
