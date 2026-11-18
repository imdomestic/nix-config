package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

type responsesInput struct {
	Model                      string
	Stream, Encrypted, Summary bool
	Gemini                     []byte
	Context                    string
	Metadata                   json.RawMessage
	ToolChoice                 json.RawMessage
}

type responsesTurn struct {
	Model       string             `json:"model"`
	Context     string             `json:"context"`
	Parts       []json.RawMessage  `json:"parts"`
	Items       []responsesVisible `json:"items"`
	ReasoningID string             `json:"reasoning_id"`
	Summary     string             `json:"summary"`
}

type responsesVisible struct {
	Type      string          `json:"type"`
	ID        string          `json:"id,omitempty"`
	Text      string          `json:"text,omitempty"`
	CallID    string          `json:"call_id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

const responsesBlobPrefix = "agy-responses-v1."

// This is the proxy's own replay format, NOT OpenAI encrypted reasoning. Only
// native model parts, prompt-context hashes and visible output go inside it;
// OAuth tokens, account/project identifiers and headers never do. Rotation of
// the proxy client key intentionally invalidates all previously issued blobs.
func responsesCipher(key string) (cipher.AEAD, error) {
	if key == "" {
		return nil, errors.New("encrypted replay requires a proxy client key")
	}
	derived := sha256.Sum256(append([]byte("agy-proxy/responses/replay/aes-gcm/v1\x00"), []byte(key)...))
	block, err := aes.NewCipher(derived[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func responsesEncrypt(key string, turn responsesTurn) (string, error) {
	return responsesEncryptBound(key, turn, maxEventBytes)
}

func responsesEncryptBound(key string, turn responsesTurn, limit int64) (string, error) {
	aead, err := responsesCipher(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	plain, err := json.Marshal(turn)
	if err != nil {
		return "", err
	}
	encodedSize := base64.RawURLEncoding.EncodedLen(len(plain)+len(nonce)+aead.Overhead()) + len(responsesBlobPrefix)
	if int64(encodedSize) > limit || encodedSize > maxEventBytes {
		return "", errors.New("encrypted replay output too large")
	}
	sealed := aead.Seal(nonce, nonce, plain, []byte(responsesBlobPrefix))
	return responsesBlobPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func responsesDecrypt(key, blob string) (responsesTurn, error) {
	var turn responsesTurn
	bad := errors.New("encrypted_content must be an intact replay blob issued by this proxy and client key")
	if !strings.HasPrefix(blob, responsesBlobPrefix) || len(blob) > maxEventBytes {
		return turn, bad
	}
	aead, err := responsesCipher(key)
	if err != nil {
		return turn, bad
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(blob, responsesBlobPrefix))
	if err != nil || len(sealed) < aead.NonceSize()+aead.Overhead() {
		return turn, bad
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte(responsesBlobPrefix))
	if err != nil || responsesStrict(plain, &turn) != nil || turn.Model == "" || turn.Context == "" || turn.ReasoningID == "" || len(turn.Parts) == 0 {
		return responsesTurn{}, bad
	}
	return turn, nil
}

func responsesStrict(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	d.UseNumber()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

func responsesObject(raw []byte, allowed string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, errors.New("expected a JSON object")
	}
	for key := range fields {
		found := false
		for _, name := range strings.Fields(allowed) {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unsupported Responses field: %s", key)
		}
	}
	return fields, nil
}

// Reject duplicate members (including inside tool schemas/arguments), trailing
// JSON, and pathological nesting before any semantic processing or credentials.
func responsesCheckJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 128 {
			return errors.New("JSON nesting limit exceeded")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate or invalid JSON member")
				}
				seen[name] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return errors.New("invalid, duplicate or excessively nested JSON")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

func responsesCanonical(raw []byte) ([]byte, error) {
	var value any
	if err := responsesStrict(raw, &value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func responsesContext(model string, system []json.RawMessage, contents []any) string {
	raw, _ := responsesCanonical(chatRaw(map[string]any{"model": model, "system": system, "contents": contents}))
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func responsesFalse(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("false"))
}
func responsesNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func responsesDecodeRequest(data []byte, key string) (responsesInput, error) {
	var input responsesInput
	if err := responsesCheckJSON(data); err != nil {
		return input, err
	}
	fields, err := responsesObject(data, "model input instructions stream store max_output_tokens temperature top_p tools tool_choice parallel_tool_calls reasoning include text metadata truncation background stream_options")
	if err != nil {
		return input, err
	}
	// These nullable SDK controls mean "use the default". In contrast store,
	// history references, tools and include are not silently weakened by null.
	for _, name := range strings.Fields("background truncation stream stream_options metadata reasoning text tool_choice parallel_tool_calls max_output_tokens temperature top_p") {
		if responsesNull(fields[name]) {
			delete(fields, name)
		}
	}
	if json.Unmarshal(fields["model"], &input.Model) != nil || !validModel(input.Model) {
		return input, errors.New("model must be a real gemini-* discovery ID, without a provider prefix")
	}
	if raw, ok := fields["store"]; ok && !responsesFalse(raw) {
		return input, errors.New("this stateless adapter supports only store=false")
	}
	if raw, ok := fields["background"]; ok && !responsesFalse(raw) {
		return input, errors.New("background responses are not supported")
	}
	if raw, ok := fields["truncation"]; ok {
		var value string
		if json.Unmarshal(raw, &value) != nil || value != "disabled" {
			return input, errors.New("only truncation=disabled is supported; replay the complete history")
		}
	}
	if raw, ok := fields["stream"]; ok && (responsesNull(raw) || json.Unmarshal(raw, &input.Stream) != nil) {
		return input, errors.New("stream must be boolean")
	}
	if raw, ok := fields["stream_options"]; ok {
		options, e := responsesObject(raw, "include_obfuscation")
		if e != nil || !input.Stream {
			return input, errors.New("stream_options requires streaming and supports only include_obfuscation=false")
		}
		if v, ok := options["include_obfuscation"]; ok && !responsesFalse(v) {
			return input, errors.New("stream obfuscation is not supported")
		}
	}
	if raw, ok := fields["include"]; ok {
		var includes []string
		if responsesNull(raw) || json.Unmarshal(raw, &includes) != nil {
			return input, errors.New("include must be an array")
		}
		for _, include := range includes {
			if include != "reasoning.encrypted_content" || input.Encrypted {
				return input, errors.New("only include=reasoning.encrypted_content is supported")
			}
			input.Encrypted = true
		}
	}
	if raw, ok := fields["metadata"]; ok {
		var metadata map[string]json.RawMessage
		if json.Unmarshal(raw, &metadata) != nil || metadata == nil || len(metadata) > 16 {
			return input, errors.New("metadata must contain at most 16 string pairs")
		}
		for k, rawValue := range metadata {
			var v string
			if responsesNull(rawValue) || json.Unmarshal(rawValue, &v) != nil {
				return input, errors.New("metadata values must be strings")
			}
			if len(k) > 64 || len(v) > 512 {
				return input, errors.New("metadata string limit exceeded")
			}
		}
		input.Metadata = raw
	}
	// Reuse the Chat decoder for its supported generation controls and schema
	// mapping only. History is decoded below without a float64 round trip.
	chat := map[string]any{"model": input.Model, "messages": []any{map[string]any{"role": "user", "content": "configuration validation"}}}
	for _, name := range []string{"temperature", "top_p", "parallel_tool_calls"} {
		if raw, ok := fields[name]; ok {
			chat[name] = raw
		}
	}
	if raw, ok := fields["max_output_tokens"]; ok {
		chat["max_completion_tokens"] = raw
	}
	if raw, ok := fields["reasoning"]; ok {
		reasoning, e := responsesObject(raw, "effort summary")
		if e != nil {
			return input, e
		}
		if effort, ok := reasoning["effort"]; ok && !responsesNull(effort) {
			chat["reasoning_effort"] = effort
		}
		if summary, ok := reasoning["summary"]; ok && !responsesNull(summary) {
			var value string
			if json.Unmarshal(summary, &value) != nil || value != "auto" {
				return input, errors.New("reasoning.summary supports only auto or null; native summary verbosity cannot be enforced")
			}
			input.Summary = true
		}
	}
	if raw, ok := fields["tools"]; ok {
		var tools []json.RawMessage
		if _, e := chatResponseBoundArray(raw, chatResponseMaxTools, nil); e != nil {
			return input, errors.New("tools array invalid or too large")
		}
		if responsesNull(raw) || json.Unmarshal(raw, &tools) != nil {
			return input, errors.New("tools must be an array of function tools")
		}
		converted := []any{}
		for _, raw := range tools {
			f, e := responsesObject(raw, "type name description parameters strict")
			if e != nil {
				return input, e
			}
			var kind string
			_ = json.Unmarshal(f["type"], &kind)
			if kind != "function" {
				return input, errors.New("hosted and non-function tools are not supported")
			}
			delete(f, "type")
			if responsesNull(f["strict"]) {
				delete(f, "strict")
			}
			if responsesNull(f["parameters"]) {
				delete(f, "parameters")
			}
			converted = append(converted, map[string]any{"type": "function", "function": f})
		}
		chat["tools"] = converted
	}
	input.ToolChoice = json.RawMessage(`"auto"`)
	if raw, ok := fields["tool_choice"]; ok {
		input.ToolChoice = raw
		var choice string
		if json.Unmarshal(raw, &choice) == nil {
			chat["tool_choice"] = choice
		} else {
			f, e := responsesObject(raw, "type name")
			if e != nil {
				return input, e
			}
			chat["tool_choice"] = map[string]any{"type": f["type"], "function": map[string]any{"name": f["name"]}}
		}
	}
	if raw, ok := fields["text"]; ok {
		text, e := responsesObject(raw, "format")
		if e != nil {
			return input, e
		}
		if raw, ok := text["format"]; ok {
			f, e := responsesObject(raw, "type name schema strict")
			if e != nil {
				return input, e
			}
			var kind string
			_ = json.Unmarshal(f["type"], &kind)
			if kind == "json_schema" {
				if responsesNull(f["strict"]) {
					delete(f, "strict")
				}
				delete(f, "type")
				chat["response_format"] = map[string]any{"type": kind, "json_schema": f}
			} else {
				if len(f) != 1 {
					return input, errors.New("non-schema text formats support only type")
				}
				chat["response_format"] = f
			}
		}
	}
	validated, err := decodeChatRequest(chatRaw(chat))
	if err != nil {
		return input, err
	}
	var gemini map[string]json.RawMessage
	_ = json.Unmarshal(validated.Gemini, &gemini)
	delete(gemini, "contents")
	// Chat validates numeric ranges, but Responses preserves the original JSON
	// numbers rather than serializing the validation decoder's float64 values.
	for source, target := range map[string]string{"temperature": "temperature", "top_p": "topP"} {
		if raw, ok := fields[source]; ok {
			var config map[string]json.RawMessage
			_ = json.Unmarshal(gemini["generationConfig"], &config)
			if config == nil {
				config = map[string]json.RawMessage{}
			}
			config[target] = raw
			gemini["generationConfig"] = chatRaw(config)
		}
	}
	if input.Summary {
		var config map[string]json.RawMessage
		_ = json.Unmarshal(gemini["generationConfig"], &config)
		if config == nil {
			config = map[string]json.RawMessage{}
		}
		var thinking map[string]json.RawMessage
		_ = json.Unmarshal(config["thinkingConfig"], &thinking)
		if thinking == nil {
			thinking = map[string]json.RawMessage{}
		}
		thinking["includeThoughts"] = chatRaw(true)
		config["thinkingConfig"] = chatRaw(thinking)
		gemini["generationConfig"] = chatRaw(config)
	}
	var system []json.RawMessage
	if raw, ok := fields["instructions"]; ok && !responsesNull(raw) {
		var instructions string
		if json.Unmarshal(raw, &instructions) != nil {
			return input, errors.New("instructions must be text or null")
		}
		system = append(system, chatRaw(map[string]any{"text": instructions}))
	}
	contents, system, err := responsesHistory(fields["input"], input.Model, key, system)
	if err != nil {
		return input, err
	}
	input.Context = responsesContext(input.Model, system, contents)
	gemini["contents"] = chatRaw(contents)
	if len(system) > 0 {
		gemini["systemInstruction"] = chatRaw(map[string]any{"role": "user", "parts": system})
	}
	input.Gemini = chatRaw(gemini)
	return input, nil
}

type responsesPending struct{ name, nativeID string }

func responsesHistory(raw json.RawMessage, model, key string, system []json.RawMessage) ([]any, []json.RawMessage, error) {
	var text string
	var items []json.RawMessage
	if json.Unmarshal(raw, &text) == nil && !responsesNull(raw) {
		items = []json.RawMessage{chatRaw(map[string]any{"role": "user", "content": text})}
	} else {
		if _, err := chatResponseBoundArray(raw, chatResponseMaxParts, nil); err != nil {
			return nil, nil, errors.New("input item array invalid or too large")
		}
		if responsesNull(raw) || json.Unmarshal(raw, &items) != nil || len(items) == 0 {
			return nil, nil, errors.New("input must be text or a nonempty full-history item array")
		}
	}
	var contents []any
	pending := map[string]responsesPending{}
	used := map[string]bool{}
	lastTool := false
	fail := func(message string) ([]any, []json.RawMessage, error) { return nil, nil, errors.New(message) }
	for i := 0; i < len(items); i++ {
		f, err := responsesObject(items[i], "type role content id status call_id name arguments output summary encrypted_content")
		if err != nil {
			return nil, nil, err
		}
		var kind string
		if tag, ok := f["type"]; ok && (responsesNull(tag) || json.Unmarshal(tag, &kind) != nil) {
			return fail("input item type must be text")
		}
		if kind != "function_call_output" {
			lastTool = false
			if len(pending) > 0 {
				return fail("every function_call needs a matching function_call_output before the next turn")
			}
		}
		switch kind {
		case "reasoning":
			turn, err := responsesReplay(items, i, model, key, responsesContext(model, system, contents))
			if err != nil {
				return nil, nil, err
			}
			call := 0
			for _, part := range turn.Parts {
				var p struct {
					Call *struct{ Name, ID string } `json:"functionCall"`
				}
				_ = json.Unmarshal(part, &p)
				if p.Call != nil {
					for call < len(turn.Items) && turn.Items[call].Type != "function_call" {
						call++
					}
					if call >= len(turn.Items) {
						return fail("invalid replay function mapping")
					}
					id := turn.Items[call].CallID
					if used[id] {
						return fail("duplicate function call_id in history")
					}
					used[id] = true
					pending[id] = responsesPending{p.Call.Name, p.Call.ID}
					call++
				}
			}
			contents = append(contents, map[string]any{"role": "model", "parts": turn.Parts})
			i += len(turn.Items)
		case "function_call":
			return fail("function_call history requires its preceding intact reasoning.encrypted_content item and complete output list")
		case "function_call_output":
			f, err = responsesObject(items[i], "type call_id output id status")
			if err != nil {
				return nil, nil, err
			}
			if err = responsesItemIdentity(f); err != nil {
				return nil, nil, err
			}
			var id string
			if json.Unmarshal(f["call_id"], &id) != nil {
				return fail("function_call_output requires call_id")
			}
			call, ok := pending[id]
			if !ok {
				return fail("orphan, duplicate or mismatched function_call_output")
			}
			delete(pending, id)
			result, media, err := responsesToolOutput(f["output"])
			if err != nil {
				return nil, nil, err
			}
			response := map[string]any{"name": call.name, "response": map[string]any{"result": result}}
			if len(media) > 0 {
				response["parts"] = media
			}
			if call.nativeID != "" {
				response["id"] = call.nativeID
			}
			part := chatRaw(map[string]any{"functionResponse": response})
			if lastTool {
				group := contents[len(contents)-1].(map[string]any)
				group["parts"] = append(group["parts"].([]json.RawMessage), part)
			} else {
				contents = append(contents, map[string]any{"role": "user", "parts": []json.RawMessage{part}})
			}
			lastTool = true
		case "", "message":
			f, err = responsesObject(items[i], "type role content id status")
			if err != nil {
				return nil, nil, err
			}
			if err = responsesItemIdentity(f); err != nil {
				return nil, nil, err
			}
			var role string
			if json.Unmarshal(f["role"], &role) != nil {
				return fail("message requires a role")
			}
			parts, err := responsesContent(f["content"], role)
			if err != nil {
				return nil, nil, err
			}
			switch role {
			case "system", "developer":
				if len(contents) > 0 {
					return fail("mid-conversation instructions cannot be reordered")
				}
				system = append(system, parts...)
			case "user", "assistant":
				if role == "assistant" {
					if _, hasID := f["id"]; hasID {
						return fail("assistant output items require their preceding encrypted reasoning item and complete output list")
					}
				}
				if len(parts) == 0 {
					return fail("empty input message")
				}
				if role == "assistant" {
					role = "model"
				}
				contents = append(contents, map[string]any{"role": role, "parts": parts})
			default:
				return fail("unsupported message role")
			}
		default:
			return fail("unsupported input item type")
		}
	}
	if len(pending) > 0 {
		return fail("missing function_call_output at end of history")
	}
	if len(contents) == 0 {
		return fail("at least one conversation turn is required")
	}
	return contents, system, nil
}

func responsesItemIdentity(f map[string]json.RawMessage) error {
	if raw, ok := f["id"]; ok {
		var id string
		if json.Unmarshal(raw, &id) != nil || id == "" {
			return errors.New("item id must be nonempty text")
		}
	}
	if raw, ok := f["status"]; ok {
		var status string
		if json.Unmarshal(raw, &status) != nil || (status != "completed" && status != "incomplete") {
			return errors.New("history items must be completed or incomplete")
		}
	}
	return nil
}

func responsesContent(raw json.RawMessage, role string) ([]json.RawMessage, error) {
	var text string
	if json.Unmarshal(raw, &text) == nil && !responsesNull(raw) {
		return []json.RawMessage{chatRaw(map[string]any{"text": text})}, nil
	}
	var list []json.RawMessage
	if _, err := chatResponseBoundArray(raw, chatResponseMaxParts, nil); err != nil {
		return nil, errors.New("content part array invalid or too large")
	}
	if responsesNull(raw) || json.Unmarshal(raw, &list) != nil {
		return nil, errors.New("message content must be text or a supported content array")
	}
	converted := []any{}
	for _, part := range list {
		var tag struct{ Type string }
		if json.Unmarshal(part, &tag) != nil {
			return nil, errors.New("invalid content part")
		}
		switch tag.Type {
		case "input_text", "output_text":
			f, err := responsesObject(part, "type text annotations logprobs")
			if err != nil {
				return nil, err
			}
			if tag.Type == "output_text" && role != "assistant" {
				return nil, errors.New("output_text is assistant-only")
			}
			for _, k := range []string{"annotations", "logprobs"} {
				if value, ok := f[k]; ok {
					var empty []json.RawMessage
					if json.Unmarshal(value, &empty) != nil || len(empty) > 0 || responsesNull(value) {
						return nil, errors.New("annotated/logprob output cannot be replayed")
					}
				}
			}
			var text string
			if json.Unmarshal(f["text"], &text) != nil || responsesNull(f["text"]) {
				return nil, errors.New("content text must be a string")
			}
			converted = append(converted, map[string]any{"type": "text", "text": text})
		case "input_image":
			f, err := responsesObject(part, "type image_url detail")
			if err != nil {
				return nil, err
			}
			var address, detail string
			if json.Unmarshal(f["image_url"], &address) != nil {
				return nil, errors.New("input_image needs an inline image_url")
			}
			if value, ok := f["detail"]; ok {
				if json.Unmarshal(value, &detail) != nil || detail != "auto" {
					return nil, errors.New("only image detail=auto is supported")
				}
			}
			converted = append(converted, map[string]any{"type": "image_url", "image_url": map[string]any{"url": address, "detail": detail}})
		case "input_video":
			f, err := responsesObject(part, "type video_url")
			if err != nil {
				return nil, err
			}
			var address string
			if json.Unmarshal(f["video_url"], &address) != nil {
				return nil, errors.New("input_video needs an inline video_url")
			}
			converted = append(converted, map[string]any{"type": "video_url", "video_url": map[string]any{"url": address}})
		case "input_audio", "image_url", "video_url", "text":
			allowed := "type " + tag.Type
			if tag.Type == "input_audio" {
				allowed = "type input_audio"
			}
			fields, err := responsesObject(part, allowed)
			if err != nil {
				return nil, err
			}
			if tag.Type == "text" {
				var value string
				if responsesNull(fields["text"]) || json.Unmarshal(fields["text"], &value) != nil {
					return nil, errors.New("content text must be a string")
				}
			}
			converted = append(converted, part)
		default:
			return nil, errors.New("unsupported Responses content part")
		}
		if role != "user" && tag.Type != "input_text" && tag.Type != "output_text" && tag.Type != "text" {
			return nil, errors.New("non-user content supports only text")
		}
	}
	return chatContent(chatRaw(converted))
}

func responsesToolOutput(raw json.RawMessage) (string, []json.RawMessage, error) {
	var text string
	if json.Unmarshal(raw, &text) == nil && !responsesNull(raw) {
		return text, nil, nil
	}
	parts, err := responsesContent(raw, "user")
	if err != nil {
		return "", nil, err
	}
	var out strings.Builder
	var media []json.RawMessage
	for _, raw := range parts {
		var p struct {
			Text   *string
			Inline *struct {
				MIME string `json:"mimeType"`
			} `json:"inlineData"`
		}
		if json.Unmarshal(raw, &p) != nil {
			return "", nil, errors.New("invalid function output")
		}
		if p.Text != nil {
			out.WriteString(*p.Text)
			continue
		}
		if p.Inline == nil || !strings.HasPrefix(p.Inline.MIME, "image/") {
			return "", nil, errors.New("function outputs support text and inline images only; audio/video results are not supported")
		}
		media = append(media, raw)
		fmt.Fprintf(&out, "[image %d]", len(media))
	}
	return out.String(), media, nil
}

func responsesSummary(raw json.RawMessage) (string, error) {
	var parts []json.RawMessage
	if len(raw) == 0 || responsesNull(raw) || json.Unmarshal(raw, &parts) != nil {
		return "", errors.New("reasoning summary must be an array of summary_text parts")
	}
	var text strings.Builder
	for _, part := range parts {
		f, err := responsesObject(part, "type text")
		if err != nil {
			return "", err
		}
		var kind, value string
		if json.Unmarshal(f["type"], &kind) != nil || kind != "summary_text" || responsesNull(f["text"]) || json.Unmarshal(f["text"], &value) != nil {
			return "", errors.New("unsupported reasoning summary part")
		}
		text.WriteString(value)
	}
	return text.String(), nil
}

func responsesReplay(items []json.RawMessage, index int, model, key, context string) (responsesTurn, error) {
	var zero responsesTurn
	f, err := responsesObject(items[index], "type id summary encrypted_content status")
	if err != nil {
		return zero, err
	}
	if err = responsesItemIdentity(f); err != nil {
		return zero, err
	}
	var blob string
	if json.Unmarshal(f["encrypted_content"], &blob) != nil {
		return zero, errors.New("reasoning history requires this proxy's encrypted_content")
	}
	turn, err := responsesDecrypt(key, blob)
	if err != nil {
		return zero, err
	}
	if turn.Model != model || turn.Context != context {
		return zero, errors.New("encrypted replay belongs to a different model or preceding prompt context; replay the complete original history")
	}
	if raw, ok := f["id"]; ok {
		var id string
		_ = json.Unmarshal(raw, &id)
		if id != turn.ReasoningID {
			return zero, errors.New("modified reasoning item id")
		}
	}
	summary, err := responsesSummary(f["summary"])
	if err != nil || summary != turn.Summary {
		return zero, errors.New("modified reasoning summary")
	}
	if len(items)-index-1 < len(turn.Items) {
		return zero, errors.New("incomplete output replay; retain the entire response.output list")
	}
	for i, want := range turn.Items {
		raw := items[index+1+i]
		var got responsesVisible
		if want.Type == "message" {
			f, e := responsesObject(raw, "type id role content status")
			if e != nil {
				return zero, e
			}
			if e = responsesItemIdentity(f); e != nil {
				return zero, e
			}
			var kind, role string
			_ = json.Unmarshal(f["type"], &kind)
			_ = json.Unmarshal(f["role"], &role)
			if (kind != "" && kind != "message") || role != "assistant" {
				return zero, errors.New("modified replay message type or role")
			}
			parts, e := responsesContent(f["content"], "assistant")
			if e != nil {
				return zero, e
			}
			var text strings.Builder
			for _, part := range parts {
				var p struct{ Text string }
				_ = json.Unmarshal(part, &p)
				text.WriteString(p.Text)
			}
			got = responsesVisible{Type: "message", Text: text.String()}
			_ = json.Unmarshal(f["id"], &got.ID)
		} else {
			f, e := responsesObject(raw, "type id call_id name arguments status")
			if e != nil {
				return zero, e
			}
			if e = responsesItemIdentity(f); e != nil {
				return zero, e
			}
			_ = json.Unmarshal(f["type"], &got.Type)
			_ = json.Unmarshal(f["id"], &got.ID)
			_ = json.Unmarshal(f["call_id"], &got.CallID)
			_ = json.Unmarshal(f["name"], &got.Name)
			var arguments string
			if json.Unmarshal(f["arguments"], &arguments) != nil || responsesCheckJSON([]byte(arguments)) != nil {
				return zero, errors.New("invalid replay function arguments")
			}
			var object map[string]json.RawMessage
			if json.Unmarshal([]byte(arguments), &object) != nil || object == nil {
				return zero, errors.New("replay function arguments must be an object")
			}
			got.Arguments, _ = responsesCanonical([]byte(arguments))
		}
		if got.ID == "" {
			got.ID = want.ID
		}
		if !sameChatJSON(chatRaw(want), chatRaw(got)) {
			return zero, errors.New("modified, missing or reordered replay output content/function arguments")
		}
	}
	return turn, nil
}
