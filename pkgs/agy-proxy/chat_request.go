package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type chatInput struct {
	Model                string
	Stream, IncludeUsage bool
	Gemini               []byte
}

type chatMessage struct {
	Role      string          `json:"role"`
	Content   json.RawMessage `json:"content"`
	Reasoning string          `json:"reasoning_content"`
	Calls     []chatInputCall `json:"tool_calls"`
	CallID    string          `json:"tool_call_id"`
	Name      string          `json:"name"`
	Extra     json.RawMessage `json:"extra_content"`
}

type chatInputCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
	Extra json.RawMessage `json:"extra_content"`
}

type chatReplay struct {
	Model string            `json:"model"`
	Parts []json.RawMessage `json:"parts"`
}

func chatBad(message string) error      { return errors.New(message) }
func chatRaw(value any) json.RawMessage { data, _ := json.Marshal(value); return data }

func decodeChatRequest(data []byte) (chatInput, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return chatInput{}, chatBad("request must be a Chat Completions JSON object")
	}
	allowed := strings.Fields("model messages stream stream_options max_tokens max_completion_tokens temperature top_p stop seed n reasoning_effort tools tool_choice parallel_tool_calls response_format store")
	for key := range fields {
		ok := false
		for _, name := range allowed {
			if key == name {
				ok = true
				break
			}
		}
		if !ok {
			return chatInput{}, chatBad("unsupported Chat Completions field: " + key)
		}
	}
	var input chatInput
	if json.Unmarshal(fields["model"], &input.Model) != nil || !validModel(input.Model) {
		return input, chatBad("model must be a real gemini-* discovery ID, without a provider prefix")
	}
	if raw, ok := fields["stream"]; ok && (bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &input.Stream) != nil) {
		return input, chatBad("stream must be boolean")
	}
	if raw, ok := fields["stream_options"]; ok {
		var opts struct {
			IncludeUsage bool `json:"include_usage"`
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&opts) != nil || !input.Stream {
			return input, chatBad("stream_options requires stream=true and only supports include_usage")
		}
		input.IncludeUsage = opts.IncludeUsage
	}
	if raw, ok := fields["store"]; ok {
		var store bool
		if json.Unmarshal(raw, &store) != nil || store {
			return input, chatBad("only store=false is supported")
		}
	}
	if raw, ok := fields["parallel_tool_calls"]; ok {
		var parallel bool
		if json.Unmarshal(raw, &parallel) != nil || !parallel {
			return input, chatBad("parallel_tool_calls=false cannot be enforced by this Gemini adapter")
		}
	}
	config := map[string]any{}
	for source, target := range map[string]string{"temperature": "temperature", "top_p": "topP"} {
		if raw, ok := fields[source]; ok {
			var v float64
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &v) != nil || (source == "temperature" && (v < 0 || v > 2)) || (source == "top_p" && (v <= 0 || v > 1)) {
				return input, chatBad("invalid sampling parameter")
			}
			config[target] = v
		}
	}
	for source, target := range map[string]string{"seed": "seed", "n": "candidateCount", "max_tokens": "maxOutputTokens", "max_completion_tokens": "maxOutputTokens"} {
		if raw, ok := fields[source]; ok {
			var v int64
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &v) != nil || (source != "seed" && v < 1) || (source == "n" && v > 8) {
				return input, chatBad("invalid integer generation parameter")
			}
			if old, ok := config[target]; ok && old != v {
				return input, chatBad("conflicting output token limits")
			}
			config[target] = v
		}
	}
	if raw, ok := fields["reasoning_effort"]; ok {
		var level string
		if json.Unmarshal(raw, &level) != nil || !strings.Contains("|minimal|low|medium|high|xhigh|", "|"+level+"|") || level == "" {
			return input, chatBad("reasoning_effort must be minimal, low, medium, high or xhigh")
		}
		config["thinkingConfig"] = map[string]any{"includeThoughts": true, "thinkingLevel": strings.ToUpper(level)}
	}
	if raw, ok := fields["stop"]; ok && !bytes.Equal(raw, []byte("null")) {
		var stops []string
		var one string
		if json.Unmarshal(raw, &one) == nil {
			stops = []string{one}
		} else if json.Unmarshal(raw, &stops) != nil {
			return input, chatBad("stop must be text or a text array")
		}
		if len(stops) > 5 {
			return input, chatBad("too many stop sequences")
		}
		for _, stop := range stops {
			if stop == "" {
				return input, chatBad("empty stop sequence")
			}
		}
		config["stopSequences"] = stops
	}
	if raw, ok := fields["response_format"]; ok {
		if err := chatResponseFormat(raw, config); err != nil {
			return input, err
		}
	}
	var messages []chatMessage
	messageDecoder := json.NewDecoder(bytes.NewReader(fields["messages"]))
	messageDecoder.DisallowUnknownFields()
	if messageDecoder.Decode(&messages) != nil || len(messages) == 0 {
		return input, chatBad("messages must be a nonempty array")
	}
	var contents []any
	var system []json.RawMessage
	pending := map[string]string{}
	nativeIDs := map[string]string{}
	lastTool := false
	for _, message := range messages {
		if message.Role != "assistant" && (message.Reasoning != "" || len(message.Calls) > 0 || len(message.Extra) > 0) {
			return input, chatBad("assistant-only reasoning and replay fields used on another role")
		}
		if message.Role != "tool" && (message.CallID != "" || message.Name != "") {
			return input, chatBad("message names and tool_call_id are supported only on tool results")
		}
		if message.Role != "tool" {
			lastTool = false
		}
		if message.Role != "tool" && len(pending) > 0 {
			return input, chatBad("every assistant tool call needs its tool result before the next message")
		}
		parts, err := chatContent(message.Content)
		if err != nil {
			return input, err
		}
		switch message.Role {
		case "system", "developer":
			if len(contents) > 0 {
				return input, chatBad("mid-conversation system messages are not supported without reordering history")
			}
			for _, part := range parts {
				var p map[string]json.RawMessage
				_ = json.Unmarshal(part, &p)
				if _, ok := p["text"]; !ok {
					return input, chatBad("system messages only support text")
				}
			}
			system = append(system, parts...)
		case "user":
			if len(message.Calls) != 0 || message.CallID != "" || message.Reasoning != "" {
				return input, chatBad("invalid user tool/reasoning fields")
			}
			if len(parts) == 0 {
				return input, chatBad("empty user message")
			}
			contents = append(contents, map[string]any{"role": "user", "parts": parts})
		case "assistant":
			for _, call := range message.Calls {
				if call.ID == "" || call.Type != "function" || call.Function.Name == "" {
					return input, chatBad("invalid function tool call")
				}
				if _, ok := pending[call.ID]; ok {
					return input, chatBad("duplicate pending tool call ID")
				}
				pending[call.ID] = call.Function.Name
			}
			replay, err := extractChatReplay(message.Extra)
			if err != nil {
				return input, err
			}
			for _, call := range message.Calls {
				candidate, err := extractChatReplay(call.Extra)
				if err != nil {
					return input, err
				}
				if candidate != nil {
					if replay != nil && !sameChatJSON(chatRaw(replay), chatRaw(candidate)) {
						return input, chatBad("conflicting native replay metadata")
					}
					replay = candidate
				}
			}
			if replay != nil {
				if err := validateChatReplay(*replay, input.Model, message, parts); err != nil {
					return input, err
				}
				parts = replay.Parts
			} else {
				if message.Reasoning != "" {
					parts = append([]json.RawMessage{chatRaw(map[string]any{"text": message.Reasoning, "thought": true})}, parts...)
				}
				for _, call := range message.Calls {
					var args map[string]json.RawMessage
					if json.Unmarshal([]byte(call.Function.Arguments), &args) != nil || args == nil {
						return input, chatBad("function arguments must be a JSON object")
					}
					part := map[string]any{"functionCall": map[string]any{"name": call.Function.Name, "args": json.RawMessage(call.Function.Arguments)}}
					var extra struct {
						Google struct {
							Signature string `json:"thought_signature"`
						} `json:"google"`
					}
					if len(call.Extra) > 0 && json.Unmarshal(call.Extra, &extra) != nil {
						return input, chatBad("invalid tool signature metadata")
					}
					if extra.Google.Signature == "" {
						return input, chatBad("Gemini tool history requires returned extra_content.agy or a native thought_signature")
					}
					part["thoughtSignature"] = extra.Google.Signature
					parts = append(parts, chatRaw(part))
				}
			}
			if len(parts) == 0 {
				return input, chatBad("empty assistant message")
			}
			callIndex := 0
			for _, raw := range parts {
				var part struct {
					Call *struct {
						ID string `json:"id"`
					} `json:"functionCall"`
				}
				_ = json.Unmarshal(raw, &part)
				if part.Call != nil {
					if part.Call.ID != "" {
						nativeIDs[message.Calls[callIndex].ID] = part.Call.ID
					}
					callIndex++
				}
			}
			contents = append(contents, map[string]any{"role": "model", "parts": parts})
		case "tool":
			name, ok := pending[message.CallID]
			if !ok || (message.Name != "" && message.Name != name) {
				return input, chatBad("tool result must reference a pending tool_call_id")
			}
			delete(pending, message.CallID)
			var text string
			for _, part := range parts {
				var p struct {
					Text *string `json:"text"`
				}
				_ = json.Unmarshal(part, &p)
				if p.Text == nil {
					return input, chatBad("tool results currently support text only; send media in a following user message")
				}
				text += *p.Text
			}
			result := map[string]any{"name": name, "response": map[string]any{"result": text}}
			if id := nativeIDs[message.CallID]; id != "" {
				result["id"] = id
				delete(nativeIDs, message.CallID)
			}
			part := map[string]any{"functionResponse": result}
			if lastTool {
				group := contents[len(contents)-1].(map[string]any)
				group["parts"] = append(group["parts"].([]any), part)
			} else {
				contents = append(contents, map[string]any{"role": "user", "parts": []any{part}})
			}
			lastTool = true
		default:
			return input, chatBad("unsupported message role")
		}
	}
	if len(pending) > 0 {
		return input, chatBad("missing tool results at end of history")
	}
	if len(contents) == 0 {
		return input, chatBad("at least one user or assistant message is required")
	}
	gemini := map[string]any{"contents": contents}
	if len(system) > 0 {
		gemini["systemInstruction"] = map[string]any{"role": "user", "parts": system}
	}
	if len(config) > 0 {
		gemini["generationConfig"] = config
	}
	if raw, ok := fields["tools"]; ok {
		tools, names, err := chatTools(raw)
		if err != nil {
			return input, err
		}
		if len(tools) > 0 {
			gemini["tools"] = []any{map[string]any{"functionDeclarations": tools}}
		}
		if raw, ok := fields["tool_choice"]; ok {
			choice, err := chatToolChoice(raw, names)
			if err != nil {
				return input, err
			}
			gemini["toolConfig"] = choice
		}
	} else if _, ok := fields["tool_choice"]; ok {
		return input, chatBad("tool_choice requires tools")
	}
	input.Gemini = chatRaw(gemini)
	return input, nil
}

func extractChatReplay(raw json.RawMessage) (*chatReplay, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var extra struct {
		AGY *chatReplay `json:"agy"`
	}
	if json.Unmarshal(raw, &extra) != nil {
		return nil, chatBad("invalid native replay metadata")
	}
	return extra.AGY, nil
}

func validateChatReplay(replay chatReplay, model string, message chatMessage, visible []json.RawMessage) error {
	if replay.Model != model || len(replay.Parts) == 0 {
		return chatBad("native replay metadata belongs to another model or has no parts")
	}
	var calls []struct {
		Name string          `json:"name"`
		Args json.RawMessage `json:"args"`
	}
	var text, thought strings.Builder
	for _, raw := range replay.Parts {
		if _, err := chatResponsePart(raw); err != nil {
			return chatBad("invalid or unsupported native replay part")
		}
		var part struct {
			Text    string `json:"text"`
			Thought bool   `json:"thought"`
			Call    *struct {
				Name string          `json:"name"`
				Args json.RawMessage `json:"args"`
			} `json:"functionCall"`
		}
		if json.Unmarshal(raw, &part) != nil {
			return chatBad("invalid native replay part")
		}
		if !part.Thought {
			text.WriteString(part.Text)
		} else {
			thought.WriteString(part.Text)
		}
		if part.Call != nil {
			calls = append(calls, *part.Call)
		}
	}
	var supplied strings.Builder
	for _, raw := range visible {
		var p struct {
			Text *string `json:"text"`
		}
		if json.Unmarshal(raw, &p) != nil || p.Text == nil {
			return chatBad("native replay conflicts with assistant media")
		}
		supplied.WriteString(*p.Text)
	}
	if strings.TrimSpace(text.String()) != strings.TrimSpace(supplied.String()) || (message.Reasoning != "" && strings.TrimSpace(message.Reasoning) != strings.TrimSpace(thought.String())) || len(calls) != len(message.Calls) {
		return chatBad("native replay no longer matches assistant content or tools")
	}
	for i, call := range calls {
		if len(call.Args) == 0 {
			call.Args = json.RawMessage(`{}`)
		}
		var before, after map[string]json.RawMessage
		if json.Unmarshal(call.Args, &before) != nil || before == nil || json.Unmarshal([]byte(message.Calls[i].Function.Arguments), &after) != nil || after == nil || call.Name != message.Calls[i].Function.Name || !sameChatJSON(call.Args, []byte(message.Calls[i].Function.Arguments)) {
			return chatBad("native replay no longer matches function arguments")
		}
	}
	return nil
}

func sameChatJSON(a, b []byte) bool {
	var x, y any
	da := json.NewDecoder(bytes.NewReader(a))
	da.UseNumber()
	db := json.NewDecoder(bytes.NewReader(b))
	db.UseNumber()
	if da.Decode(&x) != nil || db.Decode(&y) != nil {
		return false
	}
	return bytes.Equal(chatRaw(x), chatRaw(y))
}

func chatContent(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if text == "" {
			return nil, nil
		}
		return []json.RawMessage{chatRaw(map[string]any{"text": text})}, nil
	}
	var list []struct {
		Type  string `json:"type"`
		Text  string `json:"text"`
		Image struct {
			URL    string `json:"url"`
			Detail string `json:"detail"`
		} `json:"image_url"`
		Video struct {
			URL string `json:"url"`
		} `json:"video_url"`
		Audio struct {
			Data   string `json:"data"`
			Format string `json:"format"`
		} `json:"input_audio"`
		Breakpoint json.RawMessage `json:"prompt_cache_breakpoint"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&list) != nil {
		return nil, chatBad("content must be text or supported content parts")
	}
	var parts []json.RawMessage
	for _, item := range list {
		if len(item.Breakpoint) > 0 {
			return nil, chatBad("prompt_cache_breakpoint is not supported by the Gemini adapter")
		}
		if item.Type == "text" {
			parts = append(parts, chatRaw(map[string]any{"text": item.Text}))
			continue
		}
		mime, data := "", ""
		switch item.Type {
		case "image_url", "video_url":
			address := item.Image.URL
			prefix := "image/"
			if item.Type == "video_url" {
				address = item.Video.URL
				prefix = "video/"
			}
			if item.Image.Detail != "" && item.Image.Detail != "auto" {
				return nil, chatBad("image detail overrides are not supported")
			}
			head, encoded, ok := strings.Cut(address, ",")
			if !ok || !strings.HasPrefix(head, "data:"+prefix) || !strings.HasSuffix(head, ";base64") {
				return nil, chatBad("media requires an inline base64 data URL; remote URL fetching is disabled")
			}
			mime = strings.TrimSuffix(strings.TrimPrefix(head, "data:"), ";base64")
			data = encoded
		case "input_audio":
			if item.Audio.Format != "mp3" && item.Audio.Format != "wav" {
				return nil, chatBad("input_audio supports mp3 or wav")
			}
			mime = "audio/" + item.Audio.Format
			data = item.Audio.Data
		default:
			return nil, chatBad("unsupported content part type")
		}
		if strings.ContainsAny(mime, "; \r\n") || data == "" {
			return nil, chatBad("invalid inline media")
		}
		if _, err := base64.StdEncoding.DecodeString(data); err != nil {
			return nil, chatBad("invalid media base64")
		}
		parts = append(parts, chatRaw(map[string]any{"inlineData": map[string]string{"mimeType": mime, "data": data}}))
	}
	return parts, nil
}

func chatTools(raw json.RawMessage) ([]json.RawMessage, map[string]bool, error) {
	var tools []struct {
		Type     string `json:"type"`
		Function struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Parameters  json.RawMessage `json:"parameters"`
			Strict      bool            `json:"strict"`
		} `json:"function"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&tools) != nil {
		return nil, nil, chatBad("tools must be function declarations")
	}
	var declarations []json.RawMessage
	names := map[string]bool{}
	for _, tool := range tools {
		if tool.Type != "function" || tool.Function.Name == "" || tool.Function.Strict || names[tool.Function.Name] {
			return nil, nil, chatBad("invalid, duplicate or unsupported strict tool declaration")
		}
		names[tool.Function.Name] = true
		schema := tool.Function.Parameters
		if len(schema) == 0 {
			schema = chatRaw(map[string]any{"type": "object", "properties": map[string]any{}})
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(schema, &object) != nil || object == nil {
			return nil, nil, chatBad("tool parameters must be a JSON schema object")
		}
		declarations = append(declarations, chatRaw(map[string]any{"name": tool.Function.Name, "description": tool.Function.Description, "parametersJsonSchema": schema}))
	}
	return declarations, names, nil
}

func chatToolChoice(raw json.RawMessage, names map[string]bool) (any, error) {
	var choice string
	config := map[string]any{}
	if json.Unmarshal(raw, &choice) == nil {
		switch choice {
		case "auto":
			config["mode"] = "AUTO"
		case "none":
			config["mode"] = "NONE"
		case "required":
			if len(names) == 0 {
				return nil, chatBad("required tool_choice needs a function")
			}
			config["mode"] = "ANY"
		default:
			return nil, chatBad("unsupported tool_choice")
		}
	} else {
		var named struct {
			Type     string `json:"type"`
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		}
		if json.Unmarshal(raw, &named) != nil || named.Type != "function" || !names[named.Function.Name] {
			return nil, chatBad("named tool_choice must name a declared function")
		}
		config["mode"] = "ANY"
		config["allowedFunctionNames"] = []string{named.Function.Name}
	}
	return map[string]any{"functionCallingConfig": config}, nil
}

func chatResponseFormat(raw json.RawMessage, config map[string]any) error {
	var format struct {
		Type   string `json:"type"`
		Schema struct {
			Schema json.RawMessage `json:"schema"`
			Name   string          `json:"name"`
			Strict bool            `json:"strict"`
		} `json:"json_schema"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&format) != nil {
		return chatBad("invalid response_format")
	}
	switch format.Type {
	case "text":
		return nil
	case "json_object":
		config["responseMimeType"] = "application/json"
	case "json_schema":
		var object map[string]json.RawMessage
		if format.Schema.Strict || json.Unmarshal(format.Schema.Schema, &object) != nil || object == nil {
			return chatBad("response schema must be a non-strict JSON schema object")
		}
		config["responseMimeType"] = "application/json"
		config["responseJsonSchema"] = format.Schema.Schema
	default:
		return fmt.Errorf("unsupported response_format type")
	}
	return nil
}
